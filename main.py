import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# MCP & LangChain Imports
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage
from langgraph.prebuilt import create_react_agent

# --- SETUP ---
os.environ["OPENAI_API_KEY"] = ""

# Define the connection to your existing DLP Server
server_params = StdioServerParameters(
    command="uv",
    args=["run", "dlp_server.py"], 
    env=None
)

# Global variables to hold our tools/session
mcp_session = None
agent_executor = None

# --- LIFESPAN MANAGER (The Engine Starter) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    This runs BEFORE the API accepts requests.
    It starts the MCP Server and builds the Agent.
    """
    global mcp_session, agent_executor
    print("🔌 API STARTUP: Connecting to DLP MCP Server...")
    
    # Start the MCP Client (We manage the context manually here for persistence)
    # Note: For production, we'd use robust error handling for broken pipes.
    # Here we simplify by entering the stack.
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            mcp_session = session
            print("✅ API READY: Connected to MCP.")

            # --- BUILD THE TOOL ---
            @tool
            async def pattern_scanner_tool(text: str):
                """Use this to check for emails, passwords, and sensitive keywords."""
                # We use the global session
                result = await mcp_session.call_tool("scan_patterns", arguments={"text": text}) # type: ignore
                text_blocks = [c.text for c in result.content if c.type == "text"]
                return "\n".join(text_blocks)

            # --- BUILD THE AGENT ---
            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
            tools = [pattern_scanner_tool]
            
            # The "Ultimate" Persona
            system_instruction = """
            You are the Chief Information Security Officer (CISO) AI.
            Your mission is to analyze text for ANY risk to the organization.
            
            You have a 'pattern_scanner_tool' for finding basic PII. Use it first.
            
            RISK CATEGORIES (You must enforce ALL of these):
            
            1. [CRITICAL] SECRETS & INFRASTRUCTURE:
               - API Keys (AWS, OpenAI, Stripe), Private Keys, Tokens.
               - Internal IP Addresses (10.x.x.x, 192.168.x.x) or internal domains (*.corp.local).
               - Database credentials or connection strings.

            2. [HIGH] INTELLECTUAL PROPERTY (IP):
               - Proprietary Source Code (look for specific logic, not generic 'hello world').
               - Unreleased Product Codenames (e.g., "Project Skylark").
               - Patent applications or chemical formulas.

            3. [HIGH] FINANCIAL & LEGAL:
               - Insider Trading signals ("buy stock", "merger talks").
               - Non-public earnings data ("Q4 revenue is up 20%").
               - Active Lawsuit strategy or Attorney-Client privileged info.

            4. [MEDIUM] HR & SENSITIVE PERSONNEL:
               - Salary discussions ("Bob makes $150k").
               - Layoff rumors or termination lists.
               - Private medical info (HIPAA) or employee home addresses.

            DECISION LOGIC:
            - If Tool finds Pattern -> BLOCK (Reason: Regex Match).
            - If text falls into CRITICAL/HIGH categories -> BLOCK.
            - If text falls into MEDIUM -> BLOCK (unless clearly public info).
            - If text is generic conversation -> ALLOW.

            OUTPUT FORMAT:
            Final Answer must be: "VERDICT: [BLOCK/ALLOW] | CATEGORY: [Category Name] | REASON: [Brief explanation]"
            """
            
            # Create Agent
            agent_executor = create_react_agent(llm, tools)
            
            # Store the system prompt for later use
            app.state.system_prompt = system_instruction
            app.state.agent = agent_executor

            # Yield control to the application (API starts running here)
            yield
            
            print("🔌 API SHUTDOWN: Closing connections...")

# --- API DEFINITION ---
app = FastAPI(lifespan=lifespan)

# The Input Schema (Type Checking)
class ScanRequest(BaseModel):
    text: str

# The Endpoint
@app.post("/scan")
async def scan_text(request: ScanRequest):
    """
    Send text here to get a DLP verdict.
    """
    if not app.state.agent:
        raise HTTPException(status_code=503, detail="Agent not initialized")

    print(f"\n📨 REQ: Scanning {len(request.text)} chars...")

    # Inject the Persona
    messages = [
        SystemMessage(content=app.state.system_prompt),
        ("user", request.text)
    ]
    
    # Run the Agent
    response = await app.state.agent.ainvoke({"messages": messages})
    final_answer = response['messages'][-1].content
    
    # Return JSON
    return {
        "status": "success",
        "verdict_raw": final_answer
    }

# --- ENTRY POINT ---
if __name__ == "__main__":
    import uvicorn
    # Run on localhost:8000
    uvicorn.run(app, host="0.0.0.0", port=8000)
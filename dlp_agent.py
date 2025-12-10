import os
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import SystemMessage # <--- NEW IMPORT
from langgraph.prebuilt import create_react_agent

# SETUP
os.environ["OPENAI_API_KEY"] = ""


# Connect to your local DLP Server
server_params = StdioServerParameters(
    command="uv",
    args=["run", "dlp_server.py"], 
    env=None
)

async def run_dlp_scan(text_to_scan: str):
    print(f"\n🕵️ STARTING DLP SCAN FOR: \"{text_to_scan[:30]}...\"")
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # --- WRAPPER TOOL ---
            @tool
            async def pattern_scanner_tool(text: str):
                """Use this to check for emails, passwords, and sensitive keywords."""
                result = await session.call_tool("scan_patterns", arguments={"text": text})
                text_blocks = [c.text for c in result.content if c.type == "text"]
                return "\n".join(text_blocks)

            # --- THE AGENT ---
            llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
            tools = [pattern_scanner_tool]
            
            # FIX: We create the agent WITHOUT the system prompt argument
            agent_executor = create_react_agent(llm, tools)

            # --- THE PERSONA (The "Ultimate" Edition) ---
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

            # --- EXECUTION ---
            # We explicitly pass the SystemMessage at the start of the conversation
            messages = [
                SystemMessage(content=system_instruction),
                ("user", text_to_scan)
            ]
            
            response = await agent_executor.ainvoke({"messages": messages})
            print(f"\n🤖 {response['messages'][-1].content}")
            return response['messages'][-1].content
        

if __name__ == "__main__":
    
    test_cases = [
        # 1. Infrastructure Leak (Internal IP + Port)
        "Can you check why the server at 10.50.1.205 is returning 500 errors on port 8080?",
        
        # 2. HR/Salary Leak
        "I can't believe the new intern is making $120k while I'm stuck at $90k. It's unfair.",
        
        # 3. Legal/Privilege Leak
        "Forward this to legal: The lawsuit against Competitor Y is looking bad, we might settle for 5M.",
        
        # 4. API Key Leak (Subtle - Pattern Scanner might miss if not perfect regex)
        "Use this key for the prod AWS account: AKIAIOSFODNN7EXAMPLE",
        
        # 5. Safe Text (Control)
        "Hey, are we still on for lunch at 12? I'm craving pizza."
    ]

    print(f"🚀 STARTING ULTIMATE RED TEAM BATCH ({len(test_cases)} tests)\n")
    results = []
    
    for i, text in enumerate(test_cases):
        print("="*60)
        print(f"TEST #{i+1}: {text}")
        # run_dlp_scan needs to return the response
        result = asyncio.run(run_dlp_scan(text))
        results.append({"test_num": i+1, "text": text, "response": result})
        print("\n")
    
    # Display final results
    print("\n" + "="*60)
    print("📊 FINAL RESULTS SUMMARY")
    print("="*60 + "\n")
    
    for res in results:
        print(f"TEST #{res['test_num']}:")
        print(f"  Input: {res['text'][:80]}...")
        print(f"  Verdict: {res['response']}")
        print()
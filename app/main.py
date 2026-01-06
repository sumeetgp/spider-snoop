"""Main FastAPI application"""
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.database import Base, engine
from app.routes import auth, users, scans, dashboard, cdr, code_security, enterprise
from app.icap_server import ICAPServer
from app.models.user import User
from app.utils.auth import get_current_active_user

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ICAP server instance
icap_server = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    global icap_server
    
    # Startup
    logger.info("Starting Spider-Snoop DLP Application...")
    
    # Create database tables
    Base.metadata.create_all(bind=engine)
    logger.info("Database initialized")
    
    # Start ICAP server in background
    icap_server = ICAPServer()
    asyncio.create_task(icap_server.start())
    logger.info(f"ICAP server starting on {settings.ICAP_HOST}:{settings.ICAP_PORT}")
    
    # Import globally for use in error handlers
    from app.routes.scans import dlp_engine

    # --- MCP CONNECTION START ---
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        
        server_params = StdioServerParameters(
            command="python",
            args=["mcp_server.py"], # Assumes mcp_server.py is in CWD (/app)
            env=None
        )
        
        # Start Client
        from contextlib import AsyncExitStack
        stack = AsyncExitStack()
        read, write = await stack.enter_async_context(stdio_client(server_params))
        session = await stack.enter_async_context(ClientSession(read, write))
        
        # Initialize with timeout to prevent startup hang
        try:
            await asyncio.wait_for(session.initialize(), timeout=5.0)
            
            # Inject into DLPEngine
            dlp_engine.mcp_session = session
            logger.info("✅ Connected to MCP Server and injected session into DLPEngine")
        except asyncio.TimeoutError:
            logger.error("❌ MCP Connection Timed Out. Skills disabled.")
            dlp_engine.mcp_session = None

    except ImportError:
        logger.warning("MCP libraries not found. Skills disabled.")
    except Exception as e:
        logger.error(f"Failed to connect to MCP Server: {e}")
    # --- MCP CONNECTION END ---

    yield
    
    # Shutdown
    logger.info("Shutting down Spider-Snoop DLP Application...")
    if icap_server:
        await icap_server.stop()
        
    # Close MCP
    if 'stack' in locals():
        await stack.aclose()

from app.utils.limiter import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from app.core.file_guard import FileGuard
from app.middleware.security import SecurityHeadersMiddleware

# ... (rest of imports)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Data Loss Prevention System with ICAP Protocol Support",
    lifespan=lifespan,
    docs_url=None, # Disabled for custom theme
    redoc_url=None,
    openapi_url="/api/openapi.json",
)

# Custom Dark Theme for Swagger UI
from fastapi.openapi.docs import get_swagger_ui_html

@app.get("/api/docs/content", include_in_schema=False)
async def custom_swagger_ui_html(request: Request):
    nonce = request.state.nonce
    
    # Obsidian Glass Theme Injection
    dark_css = f"""
    <style nonce="{nonce}">
        body {{ background-color: #0d1117 !important; color: #c9d1d9 !important; }}
        .swagger-ui .info .title, .swagger-ui .info h1, .swagger-ui .info h2, .swagger-ui .info h3, .swagger-ui .info h4, .swagger-ui .info h5 {{ color: #c9d1d9 !important; }}
        .swagger-ui .opblock .opblock-summary-operation-id, .swagger-ui .opblock .opblock-summary-path, .swagger-ui .opblock .opblock-summary-path__deprecated {{ color: #c9d1d9 !important; }}
        .swagger-ui .opblock .opblock-summary-description {{ color: #8b949e !important; }}
        .swagger-ui .scheme-container {{ background-color: #161b22 !important; box-shadow: none !important; border-bottom: 1px solid #30363d; }}
        .swagger-ui .opblock-tag {{ color: #c9d1d9 !important; border-bottom: 1px solid #30363d; }}
        .swagger-ui .opblock {{ background: #161b22 !important; border: 1px solid #30363d; }}
        .swagger-ui .opblock .opblock-section-header {{ background: #0d1117; color: #c9d1d9; }}
        .swagger-ui .tab li {{ color: #c9d1d9 !important; }}
        .swagger-ui .btn {{ color: #c9d1d9 !important; border-color: #30363d !important; background: #21262d !important; }}
        .swagger-ui .btn:hover {{ background: #30363d !important; }}
        .swagger-ui select {{ color: #c9d1d9; background: #21262d; border-color: #30363d; }}
        .swagger-ui input {{ color: #c9d1d9 !important; background: #0d1117 !important; border: 1px solid #30363d !important; }}
        .swagger-ui textarea {{ color: #c9d1d9 !important; background: #0d1117 !important; border: 1px solid #30363d !important; }}
        .swagger-ui .dialog-ux .modal-ux {{ background: #161b22 !important; border: 1px solid #30363d; color: #c9d1d9; }}
        .swagger-ui .dialog-ux .modal-ux-header {{ border-bottom: 1px solid #30363d; }}
        .swagger-ui .expand-methods svg, .swagger-ui .expand-operation svg {{ fill: #c9d1d9 !important; }}
    </style>
    """
    
    html = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Docs",
        swagger_ui_parameters={"defaultModelsExpandDepth": -1}
    )
    # Inject Style - Decode to string, replace, then create NEW response
    # This prevents "Response content longer than Content-Length" error
    body_content = html.body.decode("utf-8")
    
    # Inject Nonce into existing Script tags
    body_content = body_content.replace("<script>", f'<script nonce="{nonce}">')
    
    # Inject Custom CSS with Nonce
    body_content = body_content.replace("</head>", f"{dark_css}</head>")
    
    return HTMLResponse(content=body_content)

@app.get("/icap/content", response_class=HTMLResponse)
async def icap_docs_content(request: Request):
    """Serve ICAP Documentation Content (Raw)"""
    return templates.TemplateResponse("icap_docs.html", {"request": request})

@app.get("/icap", response_class=HTMLResponse)
async def icap_portal(request: Request):
    """Serve ICAP Portal Wrapper"""
    template_path = Path("app/templates/icap_portal.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        return f.read()

@app.post("/api/icap/test")
async def test_icap_connection(request: Request, current_user: User = Depends(get_current_active_user)):
    """Test connectivity to local ICAP server"""
    try:
        # Get Token from current request header to pass through
        auth_header = request.headers.get("Authorization")
        
        reader, writer = await asyncio.open_connection(settings.ICAP_HOST, settings.ICAP_PORT)
        
        # Construct OPTIONS request
        req = (
            f"OPTIONS icap://{settings.ICAP_HOST}:{settings.ICAP_PORT}/respmod ICAP/1.0\r\n"
            f"Host: {settings.ICAP_HOST}\r\n"
            f"Authorization: {auth_header}\r\n"
            f"\r\n"
        )
        
        start_time = asyncio.get_event_loop().time()
        writer.write(req.encode())
        await writer.drain()
        
        # Read Response
        data = await reader.read(1024)
        latency = (asyncio.get_event_loop().time() - start_time) * 1000
        
        writer.close()
        await writer.wait_closed()
        
        response_str = data.decode()
        if "ICAP/1.0 200 OK" in response_str:
            istag = "Unknown"
            for line in response_str.split('\r\n'):
                if line.startswith("ISTag:"):
                    istag = line.split(":", 1)[1].strip()
            
            return {
                "status": "ok", 
                "message": "Connection Successful", 
                "latency_ms": round(latency, 2),
                "istag": istag
            }
        elif "401" in response_str: 
             raise HTTPException(status_code=401, detail="ICAP Auth Failed (Token rejected)")
        else:
             raise HTTPException(status_code=500, detail=f"Unexpected ICAP Response: {response_str[:50]}...")
             
    except Exception as e:
        logger.error(f"ICAP Test Failed: {e}")
        raise HTTPException(status_code=502, detail=f"Failed to connect to ICAP server: {str(e)}")

app.state.limiter = limiter
app.state.file_guard = FileGuard()
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(scans.router)
app.include_router(dashboard.router)
app.include_router(cdr.router)
app.include_router(code_security.router)
app.include_router(enterprise.router)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint with dashboard"""
    template_path = Path("app/templates/index.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        html_content = f.read()
    
    # Replace placeholders
    html_content = html_content.replace("{{ICAP_PORT}}", str(settings.ICAP_PORT))
    html_content = html_content.replace("{{ICAP_SERVICE_NAME}}", settings.ICAP_SERVICE_NAME)
    html_content = html_content.replace("{{ nonce }}", request.state.nonce)
    
    return HTMLResponse(content=html_content)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard endpoint"""
    template_path = Path("app/templates/dashboard.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        html_content = f.read()
    
    # Replace placeholders if any
    html_content = html_content.replace("{{ICAP_PORT}}", str(settings.ICAP_PORT))
    html_content = html_content.replace("{{ICAP_SERVICE_NAME}}", settings.ICAP_SERVICE_NAME)
    html_content = html_content.replace("{{ nonce }}", request.state.nonce)
    
    return HTMLResponse(content=html_content)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Login page"""
    template_path = Path("app/templates/login.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        html_content = f.read()
    
    html_content = html_content.replace("{{ nonce }}", request.state.nonce)
    return HTMLResponse(content=html_content)

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    """Registration page"""
    template_path = Path("app/templates/register.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        html_content = f.read()
    
    html_content = html_content.replace("{{ nonce }}", request.state.nonce)
    return HTMLResponse(content=html_content)

@app.get("/about", response_class=HTMLResponse)
async def about_page():
    """About Us page"""
    template_path = Path("app/templates/about.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        return f.read()

@app.get("/enterprise", response_class=HTMLResponse)
async def enterprise_page():
    """Enterprise page"""
    template_path = Path("app/templates/enterprise.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        return f.read()

@app.get("/api/docs", response_class=HTMLResponse)
async def api_docs_page(request: Request):
    """API Documentation Wrapper page"""
    template_path = Path("app/templates/api_docs.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        html_content = f.read()
    
    html_content = html_content.replace("{{ nonce }}", request.state.nonce)
    return HTMLResponse(content=html_content)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )

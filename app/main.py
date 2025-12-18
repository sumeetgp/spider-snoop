"""Main FastAPI application"""
import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.database import Base, engine
from app.routes import auth, users, scans, dashboard
from app.icap_server import ICAPServer

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
    
    yield
    
    # Shutdown
    logger.info("Shutting down Spider-Snoop DLP Application...")
    if icap_server:
        await icap_server.stop()

from app.utils.limiter import limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from app.core.file_guard import FileGuard

# ... (rest of imports)

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Data Loss Prevention System with ICAP Protocol Support",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    swagger_ui_init_oauth={
        "clientId": "",
        "clientSecret": "",
        "usePkceWithAuthorizationCodeGrant": False
    }
)

app.state.limiter = limiter
app.state.file_guard = FileGuard()
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
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

# Mount static files and templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with dashboard"""
    template_path = Path("app/templates/index.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        html_content = f.read()
    
    # Replace placeholders
    html_content = html_content.replace("{{ICAP_PORT}}", str(settings.ICAP_PORT))
    html_content = html_content.replace("{{ICAP_SERVICE_NAME}}", settings.ICAP_SERVICE_NAME)
    
    return html_content

@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Login page"""
    template_path = Path("app/templates/login.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        return f.read()

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    """Registration page"""
    template_path = Path("app/templates/register.html")
    if not template_path.exists():
        return HTMLResponse(content="<h1>Error: Template not found</h1>", status_code=500)
    with open(template_path, "r") as f:
        return f.read()

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

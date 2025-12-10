"""Main FastAPI application"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

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

# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Data Loss Prevention System with ICAP Protocol Support",
    lifespan=lifespan
)

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

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Spider-Snoop DLP</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 20px;
            }
            .card {
                background: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .endpoint {
                background: #f8f9fa;
                padding: 15px;
                margin: 10px 0;
                border-left: 4px solid #667eea;
            }
            .method {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-weight: bold;
                margin-right: 10px;
            }
            .get { background: #61affe; color: white; }
            .post { background: #49cc90; color: white; }
            .put { background: #fca130; color: white; }
            .delete { background: #f93e3e; color: white; }
            code {
                background: #f4f4f4;
                padding: 2px 6px;
                border-radius: 3px;
                font-family: 'Courier New', monospace;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🕷️ Spider-Snoop DLP</h1>
            <p>Data Loss Prevention System with AI-Powered Scanning</p>
        </div>
        
        <div class="card">
            <h2>📊 System Status</h2>
            <p>✅ API Server: Running</p>
            <p>✅ ICAP Server: Running on port """ + str(settings.ICAP_PORT) + """</p>
            <p>✅ Database: Connected</p>
        </div>
        
        <div class="card">
            <h2>🚀 Quick Start</h2>
            <p>1. <strong>API Documentation:</strong> <a href="/docs">Interactive API Docs</a></p>
            <p>2. <strong>Alternative Docs:</strong> <a href="/redoc">ReDoc</a></p>
            <p>3. <strong>ICAP Configuration:</strong> Point your DLP client to <code>icap://localhost:""" + str(settings.ICAP_PORT) + "/" + settings.ICAP_SERVICE_NAME + """</code></p>
        </div>
        
        <div class="card">
            <h2>🔐 Authentication</h2>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/auth/login</code>
                <p>Login with username and password to get access token</p>
            </div>
        </div>
        
        <div class="card">
            <h2>👥 User Management</h2>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/users/me</code>
                <p>Get current user information</p>
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/users/</code>
                <p>List all users (Admin/Analyst only)</p>
            </div>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/users/</code>
                <p>Create new user (Admin only)</p>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 DLP Scanning</h2>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/scans/</code>
                <p>Create and execute a DLP scan</p>
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/scans/</code>
                <p>List all scans</p>
            </div>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/scans/stats</code>
                <p>Get scanning statistics</p>
            </div>
        </div>
        
        <div class="card">
            <h2>📈 Dashboard</h2>
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/dashboard/overview</code>
                <p>Get dashboard overview with statistics and trends</p>
            </div>
        </div>
        
        <div class="card">
            <h2>🔧 Features</h2>
            <ul>
                <li>✅ User Authentication & Authorization (JWT)</li>
                <li>✅ Role-Based Access Control (Admin, Analyst, Viewer)</li>
                <li>✅ AI-Powered DLP Scanning</li>
                <li>✅ ICAP Protocol Support</li>
                <li>✅ Pattern-Based Detection (Credit Cards, SSN, API Keys, etc.)</li>
                <li>✅ Real-time Dashboard & Analytics</li>
                <li>✅ RESTful API</li>
                <li>✅ Database Persistence</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>📚 Detected Data Types</h2>
            <ul>
                <li>💳 Credit Card Numbers</li>
                <li>🆔 Social Security Numbers (SSN)</li>
                <li>📧 Email Addresses</li>
                <li>📞 Phone Numbers</li>
                <li>🌐 IP Addresses</li>
                <li>🔑 API Keys & Tokens</li>
                <li>☁️ AWS Access Keys</li>
            </ul>
        </div>
    </body>
    </html>
    """

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

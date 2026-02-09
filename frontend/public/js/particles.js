class ParticleNetwork {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.mouse = { x: null, y: null, radius: 150 };
        this.init();
    }

    init() {
        this.resize();
        window.addEventListener('resize', () => this.resize());
        window.addEventListener('mousemove', (e) => {
            this.mouse.x = e.x;
            this.mouse.y = e.y;
        });
        window.addEventListener('mouseout', () => {
            this.mouse.x = null;
            this.mouse.y = null;
        });

        this.createParticles();
        this.animate();
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.createParticles(); // Recreate on resize for distribution
    }

    createParticles() {
        this.particles = [];
        const numberOfParticles = (this.canvas.width * this.canvas.height) / 20000;
        for (let i = 0; i < numberOfParticles; i++) {
            const size = (Math.random() * 2) + 1;
            const x = (Math.random() * ((this.canvas.width - size * 2) - (size * 2)) + size * 2);
            const y = (Math.random() * ((this.canvas.height - size * 2) - (size * 2)) + size * 2);
            const directionX = (Math.random() * 0.4) - 0.2;
            const directionY = (Math.random() * 0.4) - 0.2;
            const color = Math.random() > 0.5 ? '#88ffff' : '#00e5ff'; // Neon Blue or Cyan

            this.particles.push({
                x, y, directionX, directionY, size, color
            });
        }
    }

    animate() {
        requestAnimationFrame(() => this.animate());
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        for (let i = 0; i < this.particles.length; i++) {
            const p = this.particles[i];

            // Movement
            p.x += p.directionX;
            p.y += p.directionY;

            // Wall collision
            if (p.x > this.canvas.width || p.x < 0) p.directionX = -p.directionX;
            if (p.y > this.canvas.height || p.y < 0) p.directionY = -p.directionY;

            // Mouse Interaction (Repulsion)
            if (this.mouse.x != null) {
                let dx = this.mouse.x - p.x;
                let dy = this.mouse.y - p.y;
                let distance = Math.sqrt(dx * dx + dy * dy);
                if (distance < this.mouse.radius) {
                    if (this.mouse.x < p.x && p.x < this.canvas.width - p.size * 10) p.x += 2;
                    if (this.mouse.x > p.x && p.x > p.size * 10) p.x -= 2;
                    if (this.mouse.y < p.y && p.y < this.canvas.height - p.size * 10) p.y += 2;
                    if (this.mouse.y > p.y && p.y > p.size * 10) p.y -= 2;
                }
            }

            // Draw Particle
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2, false);
            this.ctx.fillStyle = p.color;
            this.ctx.fill();

            // Connect Particles
            this.connect(p, i);
        }
    }

    connect(p, i) {
        // Only verify against a subset to save performance, or all
        for (let j = i + 1; j < this.particles.length; j++) {
            const p2 = this.particles[j];
            let distance = ((p.x - p2.x) * (p.x - p2.x)) + ((p.y - p2.y) * (p.y - p2.y));
            if (distance < (this.canvas.width / 9) * (this.canvas.height / 9)) {
                let opacityValue = 1 - (distance / 15000);
                if (opacityValue > 0) {
                    this.ctx.strokeStyle = `rgba(136, 255, 255, ${opacityValue})`;
                    this.ctx.lineWidth = 1;
                    this.ctx.beginPath();
                    this.ctx.moveTo(p.x, p.y);
                    this.ctx.lineTo(p2.x, p2.y);
                    this.ctx.stroke();
                }
            }
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new ParticleNetwork('bgCanvas');
});

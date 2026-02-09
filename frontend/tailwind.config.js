/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                bg: '#0D1117',
                card: '#161B22',
                glass: 'rgba(22, 27, 34, 0.7)',
                border: '#30363d',
                brand: '#88FFFF',
                success: '#238636',
                warning: '#D29922',
                alert: '#F85149',
                text: '#C9D1D9'
            },
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
                mono: ['JetBrains Mono', 'monospace'],
            }
        },
    },
    plugins: [],
}

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#090d16",
          card: "#0f172a",
          cardHover: "#172033",
          border: "#1e293b",
          primary: "#06b6d4",    // Cyan
          success: "#10b981",    // Emerald
          warning: "#f59e0b",    // Amber
          danger: "#f43f5e",     // Rose Red
          accent: "#8b5cf6",     // Violet
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'Menlo', 'Monaco', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
      },
      animation: {
        'pulse-fast': 'pulse 1.2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(6, 182, 212, 0.3)' },
          '100%': { boxShadow: '0 0 18px rgba(6, 182, 212, 0.7)' },
        }
      }
    },
  },
  plugins: [],
}

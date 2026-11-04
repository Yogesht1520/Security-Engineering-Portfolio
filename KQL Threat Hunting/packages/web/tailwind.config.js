/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          app: '#0B0F14',
          surface: '#111821',
          raised: '#18212C',
          border: '#243040',
          text: '#E6EDF3',
          muted: '#9AA7B4',
          accent: '#3B82F6',
          highlight: '#22D3EE',
          severity: {
            info: '#64748B',
            low: '#22C55E',
            medium: '#F59E0B',
            high: '#EF4444'
          },
          validation: {
            syntax: '#64748B',
            synthetic: '#3B82F6',
            tenant: '#22C55E'
          }
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace']
      },
      borderRadius: {
        soc: '6px'
      }
    },
  },
  plugins: [],
}


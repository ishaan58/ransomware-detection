/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        primary: "#6366f1",
        accent: "#22c55e",
      },
    },
  },
  theme: {
  extend: {
    keyframes: {
      fadeIn: { "0%": { opacity: 0 }, "100%": { opacity: 1 } },
    },
    animation: {
      fadeIn: "fadeIn 1s ease-in-out",
      fadeInSlow: "fadeIn 1.5s ease-in-out",
    },
  },
},

  plugins: [],
};

// theme.js

/**
 * Toggles the 'dark' class on the root HTML element.
 * Updates the theme preference in localStorage.
 * Updates the icon in the theme toggle button.
 */
function toggleTheme() {
    const html = document.documentElement;
    const isDark = html.classList.toggle('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    updateThemeIcon(isDark);
}

/**
 * Initializes the theme on page load.
 * It checks localStorage for a preference or defaults to the system preference.
 */
function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    let themeToApply = 'light';

    if (savedTheme) {
        themeToApply = savedTheme;
    } else if (prefersDark) {
        themeToApply = 'dark';
    }

    const isDark = themeToApply === 'dark';
    if (isDark) {
        document.documentElement.classList.add('dark');
    }
    updateThemeIcon(isDark);

    // Attach the toggle function to the button
    const themeToggleBtn = document.getElementById('theme-toggle');
    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
    }
}

/**
 * Updates the sun/moon icon based on the current theme.
 */
function updateThemeIcon(isDark) {
    const iconContainer = document.getElementById('theme-toggle-icon');
    if (iconContainer) {
        if (isDark) {
            // Moon icon (for light mode toggle, meaning currently dark)
            iconContainer.innerHTML = `<svg class="w-6 h-6 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path></svg>`;
        } else {
            // Sun icon (for dark mode toggle, meaning currently light)
            iconContainer.innerHTML = `<svg class="w-6 h-6 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>`;
        }
    }
}

// Run the initialization function when the document is loaded
document.addEventListener('DOMContentLoaded', initTheme);
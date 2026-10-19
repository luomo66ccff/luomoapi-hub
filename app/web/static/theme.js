(() => { try { const theme = localStorage.getItem('luomoapi-theme'); if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme; } catch {} })();

// Fetch movies from the backend
fetch('/movies')
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('movie-container');
        if (data && data.length > 0) {
            data.forEach(movie => {
                const movieDiv = document.createElement('div');
                movieDiv.className = 'movie-item';
                movieDiv.innerHTML = `
                    <img src="${movie.big_image}" alt="${movie.title}">
                `;
                container.appendChild(movieDiv);
            });
        } else {
            container.innerHTML = '<p>No movies available.</p>';
        }
    })
    .catch(error => console.error('Error fetching movies:', error));

// Scroll functions
// Fetch news from the backend
fetch('/news')
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('news-container');
        if (data && data.length > 0) {
            data.forEach(news => {
                const newsDiv = document.createElement('div');
                newsDiv.className = 'news-item';
                newsDiv.innerHTML = `
                    <h4><a href="${news.link}" target="_blank">${news.title}</a></h4>
                    <p>${news.summary}</p>
                    <span>Source: ${news.source}</span>
                `;
                container.appendChild(newsDiv);
            });
        } else {
            container.innerHTML = '<p>No news available.</p>';
        }
    })
    .catch(error => console.error('Error fetching news:', error));


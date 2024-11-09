CREATE DATABASE movie_stock_market;

CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    profile_picture VARCHAR(255), 
    PRIMARY KEY (user_id)
);

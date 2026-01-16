# News Aggregator API 📰

A RESTful API built with Node.js and Express that fetches news articles based on user preferences.

## 🚀 Features
* **User Registration:** Secure signup with hashed passwords.
* **Authentication:** JWT-based login system.
* **Personalized News:** Fetch news based on user preferences (e.g., Sports, Tech).
* **Data Persistence:** Uses a file-based database (`users.json`).
* **External Integration:** Fetches real-time data from NewsAPI.

## 🔌 API Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/register` | Register a new user |
| `POST` | `/login` | Login and get Token |
| `GET` | `/news` | Get personalized news (Requires Token) |
| `PUT` | `/preferences` | Update news preferences (Requires Token) |

## 🧪 How to Run
1. Install dependencies: `npm install`
2. Create `.env` file with `PORT` and `API_KEY`.
3. Start server: `node app.js`
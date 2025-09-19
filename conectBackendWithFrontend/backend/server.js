import express from "express";
import cors from "cors";

const app = express();
app.use(cors());

app.get("/", (req, res) => {
  res.send("Server is ready");
});
const port = process.env.PORT || 3000;

app.get("/api/jokes", (req, res) => {
  const jokes = [
    {
      id: 1,
      joke: "Why did the developer go broke? Because he used up all his cache.",
    },
    {
      id: 2,
      joke: "Why do programmers prefer dark mode? Because light attracts bugs!",
    },
    {
      id: 3,
      joke: "Why did the function return early? Because it had a date with an exception.",
    },
    {
      id: 4,
      joke: "Why was the JavaScript developer sad? Because he didn't know how to 'null' his feelings.",
    },
    {
      id: 5,
      joke: "Why do Java developers wear glasses? Because they don't C#.",
    },
  ];
  res.send(jokes);
});

app.listen(port, () => {
  console.log("Server is running on port 3000");
});

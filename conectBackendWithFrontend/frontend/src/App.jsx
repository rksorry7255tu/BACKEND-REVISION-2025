import "./App.css";
import { useEffect, useState } from "react";
import axios from "axios";

function App() {
  const [jokes, setJokes] = useState();
  useEffect(() => {
    axios
      .get("/api/jokes")
      .then((response) => {
        setJokes(response.data);
        console.log(response.data);
      })
      .catch((error) => {
        console.log(error);
      });
  });

  return (
    <>
      <h1> Hello from Ravi</h1>
      <p>Jokes</p>
      {jokes.map((joke, index) => (
        <div key={joke.id}>
          <h1>{joke.id}</h1>
          <p>{joke.joke}</p>
        </div>
      ))}
    </>
  );
}

export default App;

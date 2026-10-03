const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const todos = [];
app.get('/todos', (_request, response) => response.json(todos));
app.post('/todos', (request, response) => {
  const todo = { id: todos.length + 1, title: request.body.title };
  todos.push(todo);
  response.status(201).json(todo);
});

app.listen(3000);

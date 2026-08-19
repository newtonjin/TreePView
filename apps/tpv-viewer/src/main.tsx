import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ContextMenuHost } from "./components/ContextMenu";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ContextMenuHost>
      <App />
    </ContextMenuHost>
  </React.StrictMode>,
);

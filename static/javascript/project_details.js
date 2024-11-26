// static/javascript/project_details.js

document.addEventListener("DOMContentLoaded", () => {
  // Ensure project_id is defined
  if (typeof project_id === "undefined") {
    console.error("project_id is not defined.");
    return;
  }

  console.log("Project ID:", project_id);

  var socket = io.connect(
    location.protocol + "//" + document.domain + ":" + location.port
  );

  if (typeof socket === "undefined") {
    console.error("SocketIO connection failed.");
    return;
  }

  const projectId = parseInt(project_id); // Ensure project_id is an integer
  if (isNaN(projectId)) {
    console.error("Invalid project_id:", project_id);
    return;
  }

  const room = `project_${projectId}`;

  console.log("Connecting to room:", room);

  // Join room
  socket.emit("join", { project_id: projectId });
  console.log("Join event emitted.");

  // Handle incoming messages
  socket.on("message", (data) => {
    console.log("New message received:", data);
    const msgList = document.getElementById("messages");
    const msgItem = document.createElement("li");
    msgItem.classList.add("mb-3", "d-flex", "align-items-start");

    // Create profile picture element
    const profileLink = document.createElement("a");
    profileLink.href = data.profile_url; // Ensure data includes profile_url

    const profileImg = document.createElement("img");
    profileImg.src = data.profile_picture_url; // Ensure data includes profile_picture_url
    profileImg.alt = data.username;
    profileImg.classList.add("profile-pic", "rounded-circle", "mr-3");
    profileImg.width = 40;
    profileImg.height = 40;

    profileLink.appendChild(profileImg);

    // Create message content
    const messageContent = document.createElement("div");
    messageContent.innerHTML = `<strong>${data.username}</strong>: ${data.message} <br><small class="text-muted">${data.timestamp}</small>`;

    // Append elements to message item
    msgItem.appendChild(profileLink);
    msgItem.appendChild(messageContent);

    msgList.appendChild(msgItem);
    msgList.scrollTop = msgList.scrollHeight; // Auto-scroll to the latest message
  });

  // Handle status messages
  socket.on("status", (data) => {
    console.log("Status update:", data);
    const msgList = document.getElementById("messages");
    const msgItem = document.createElement("li");
    msgItem.classList.add("mb-3", "d-flex", "align-items-center");
    msgItem.innerHTML = `<em>${data.msg}</em>`;
    msgList.appendChild(msgItem);
    msgList.scrollTop = msgList.scrollHeight;
  });

  // Send messages
  document.getElementById("chat-form").onsubmit = (e) => {
    e.preventDefault(); // Prevent page refresh
    const messageInput = document.getElementById("message");
    const message = messageInput.value.trim();
    if (message.length > 0) {
      console.log("Sending message:", message);
      socket.emit("message", { message: message, project_id: projectId });
      messageInput.value = "";
    }
  };
});

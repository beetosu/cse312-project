
// Establish a WebSocket connection with the server
const socket = new WebSocket('ws://' + window.location.host + '/websocket');

// Call the addMessage function whenever data is received from the server over the WebSocket
socket.onmessage = addMessage;

// Allow users to send messages by pressing enter instead of clicking the Send button
document.addEventListener("keypress", function (event) {
   if (event.code === "Enter") {
       sendMessage();
   }
});

// Read the name/comment the user is sending to chat and send it to the server over the WebSocket as a JSON string
// Called whenever the user clicks the Send button or pressed enter
function sendMessage() {
   const chatName = document.getElementById("chat-name").value;
   const chatBox = document.getElementById("chat-comment");
   const comment = chatBox.value;
   chatBox.value = "";
   chatBox.focus();
   if(comment !== "") {
       socket.send(JSON.stringify({'username': chatName, 'comment': comment}));
   }
}


//Fetch get requests and getting the channel get the user1 and user2 authenticate user1 cookie and token 

//CHeck out fetch documentation Sent api request to python server 

//Authenticate user 1 and and get the channel between the two

//DO 2 thero



fetch('/users')
   .then(data=>{

   })

// Called when the server sends a new message over the WebSocket and renders that message so the user can read it
function addMessage(message) {
   const chatMessage = JSON.parse(message.data);
   let chat = document.getElementById('chat');
   chat.innerHTML += "<b>" + chatMessage['username'] + "</b>: " + chatMessage["comment"] + "<br/>";
}


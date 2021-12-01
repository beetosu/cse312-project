const UserStatusUpdate = document.getElementById("userStatusUpdate")

if (navigator.onLine) {
    UserStatusUpdate.textContent = "Online";
    UserStatusUpdate.style.color = "green";
}

window.addEventListener("online", function (){
    UserStatusUpdate.textContent = "Online";
    UserStatusUpdate.style.color = "green";
});

window.addEventListener("offline", function (){
    UserStatusUpdate.textContent = "Offline";
    UserStatusUpdate.style.color = "red";
});
//Look up on websocket functionality
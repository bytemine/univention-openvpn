function otp_popup() {
  var popup = document.getElementById("otppopup");
  popup.classList.add("show");
  setTimeout(() => popup.classList.remove("show"), 9999) 
}

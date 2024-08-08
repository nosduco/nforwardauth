/* Utility Functions */
const params = new Proxy(new URLSearchParams(window.location.search), {
  get: (searchParams, prop) => searchParams.get(prop),
});

const displayAlert = (msg, variant) => {
  const alertContainer = document.querySelector(".alert");
  const alertMessage = document.getElementById("alert-message");

  alertContainer.classList.remove("success", "error");
  alertContainer.classList.add(variant);
  alertMessage.innerText = msg;
  alertContainer.style.display = "block";
  setTimeout(() => {
    alertContainer.style.opacity = "1";
  }, 10);
};

const handleError = (err) => {
  // Unexpected error occurred, show alert
  displayAlert("Unexpected error occurred.", "error");
  console.log("Error occurred", err);
  setFieldsDisabled(false);
};

const handleResponse = (res) => {
  switch (res.status) {
    case 200:
      // Logged out successfully.
      displayAlert(
        "You have successfully logged out, redirecting to login...",
        "success"
      );
      setInterval(() => {
        window.location.replace("/login");
      }, 2000);
      break;
    default:
      // Unexpected status code
      displayAlert("Unexpected response from server.", "error");
      setFieldsDisabled(false);
      break;
  }
};

// Logout function
const logout = (event) => {
  // override default form behaviour
  event.preventDefault();

  // Disable fields until after request
  setFieldsDisabled(true);

  // Sent HTTP request
  fetch("/logout", {
    method: "post",
    body: JSON.stringify({}),
    headers: { "Content-Type": "application/json" },
  })
    .then(handleResponse)
    .catch(handleError);
};

const setFieldsDisabled = (disabled) => {
  // Set fields disabled attributes
  document.getElementById("submit").disabled = disabled;
};

// Configure form to trigger logout
var form = document.querySelector("form");
form.onsubmit = logout;

// Set banner if just logged in
if (params.success) {
  displayAlert("You have successfully logged in.", "success");
}

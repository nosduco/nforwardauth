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
      // Authenticated, redirect to referral (if exists)
      if (params.r) {
        window.location.replace(params.r);
      } else {
        // Redirect to logout page
        window.location.replace("/logout?success=true");
      }
      break;
    case 401:
      // Bad credentials
      document.getElementById("password").value = "";
      displayAlert("Incorrect credentials.", "error");
      setFieldsDisabled(false);
      break;
    default:
      // Unexpected status code
      displayAlert("Unexpected response from server.", "error");
      setFieldsDisabled(false);
      break;
  }
};

// Login function
const login = (event) => {
  // override default form behaviour
  event.preventDefault();

  // Get form values
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  // Create data object to send
  const data = {
    username,
    password,
  };

  // Disable fields until after request
  setFieldsDisabled(true);

  // Sent HTTP request
  fetch("/login", {
    method: "post",
    body: JSON.stringify(data),
    headers: { "Content-Type": "application/json" },
  })
    .then(handleResponse)
    .catch(handleError);
};

const setFieldsDisabled = (disabled) => {
  // Set fields disabled attributes
  document.getElementById("username").disabled = disabled;
  document.getElementById("password").disabled = disabled;
  document.getElementById("submit").disabled = disabled;
};

// Configure form to trigger login
var form = document.querySelector("form");
form.onsubmit = login;

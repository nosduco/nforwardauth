// Configure submit button click to trigger login
const submitButton = document.getElementById("submit");
submitButton.onclick = login;

// Login function
const login = () => {
  // Get form values
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  // Validation
  if (username == "" || password == "") {
    alert("Please make sure all fields are filled.");
    return;
  }

  // Create data object to send
  const data = {
    username,
    password,
  };

  // Sent HTTP request
  fetch("/login", data)
    .then((res) => {
      console.log(res);
    })
    .catch((error) => console.log(error));
};

const setFieldsDisabled = (disabled) => {
  // Set fields disabled attributes
  document.getElementById("username").disabled = disabled;
  document.getElementById("password").disabled = disabled;
  document.getElementById("submit").disabled = disabled;
};

// Handle Response Function
const handleResponse = (res) => {
  switch (res.status) {
    case 401:
      // wrong password
      alert("Invalid credentials.");
      break;
    case 200:
      alert("good");
      break;
    default:
      break;
  }
};

// Handle Error Function
const handleError = (err) => {
  console.log("Hello");
  console.err(JSON.stringify(err));
};

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

// Configure submit button click to trigger login
const submitButton = document.getElementById("submit");
submitButton.onclick = login;
console.log("Hello");

const testbutton = document.getElementById("test");
testbutton.onclick = () => {
  // Sent HTTP request
  fetch("/forward")
    .then((res) => console.log(res));
};

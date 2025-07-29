// web/vault.js

document.addEventListener('DOMContentLoaded', () => {
	const logoutBtn = document.getElementById('logoutBtn');
	const credentialsTableBody = document.querySelector(
		'#credentialsTable tbody',
	);
	const noCredentialsMessage = document.getElementById(
		'noCredentialsMessage',
	);
	const addCredentialForm = document.getElementById('addCredentialForm');
	const messageDiv = document.getElementById('message');

	// --- Helper Functions ---

	/**
	 * Displays a message to the user.
	 * @param {string} text - The message text.
	 * @param {string} type - 'success', 'error', or 'info'.
	 */
	function showMessage(text, type = 'info') {
		messageDiv.textContent = text;
		messageDiv.className = `message ${type}`;
		messageDiv.style.display = 'block';
		// Hide message after a few seconds
		setTimeout(() => {
			messageDiv.style.display = 'none';
		}, 5000);
	}

	/**
	 * Checks if a user is logged in (based on localStorage) and redirects if not.
	 */
	async function checkLoginStatus() {
		try {
			const response = await fetch('/api/status');
			const data = await response.json();

			if (!response.ok) {
				window.location.href = 'index.html'; // Redirect to login if not logged in
			}
			console.log(data);
			if (data.logstatus == true) {
				return;
			} else {
				window.location.href = 'index.html'; // Redirect to login if not logged in
			}
		} catch { }
		const username = localStorage.getItem('loggedInUser');
		if (!username) {
			window.location.href = 'index.html'; // Redirect to login if not logged in
		}
	}

	/**
	 * Fetches and renders credentials from the backend.
	 */
	async function fetchAndRenderCredentials() {
		try {
			const response = await fetch('/api/credentials');
			const data = await response.json();

			if (!response.ok) {
				throw new Error(data.error || 'Failed to fetch credentials');
			}

			credentialsTableBody.innerHTML = ''; // Clear existing rows

			if (data.length === 0) {
				noCredentialsMessage.style.display = 'block';
				credentialsTableBody.style.display = 'none';
			} else {
				noCredentialsMessage.style.display = 'none';
				credentialsTableBody.style.display = 'table-row-group'; // Ensure tbody is visible
				data.forEach((cred) => {
					const row = credentialsTableBody.insertRow();
					row.insertCell(0).textContent = cred.url;
					row.insertCell(1).textContent = cred.username;
					row.insertCell(2).textContent = cred.password; // This will be masked from backend
					row.insertCell(3).textContent = cred.notes || '';
				});
			}
		} catch (error) {
			console.error('Error fetching credentials:', error);
			showMessage(`Error loading credentials: ${error.message}`, 'error');
		}
	}

	// --- Event Listeners ---

	// Check login status on page load
	checkLoginStatus();
	fetchAndRenderCredentials(); // Fetch credentials if logged in

	// Logout button handler
	logoutBtn.addEventListener('click', async () => {
		try {
			const response = await fetch('/api/signout', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
			});

			if (!response.ok) {
				throw new Error(data.error || 'Logout failed');
			}

			showMessage('Logged out successfully. Redirecting...', 'success');
			setTimeout(() => {
				window.location.href = 'index.html';
			}, 1000); // Give time for message to display
		} catch (error) {
			console.error('Error during logout:', error);
			showMessage(`Logout error: ${error.message}`, 'error');
		}
	});

	// Add Credential form handler
	addCredentialForm.addEventListener('submit', async (event) => {
		event.preventDefault(); // Prevent default form submission

		const newUrl = document.getElementById('newUrl').value;
		const newUsername = document.getElementById('newUsername').value;
		const newPassword = document.getElementById('newPassword').value;
		const newNotes = document.getElementById('newNotes').value;

		try {
			const response = await fetch('/api/add-credential', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({
					url: newUrl,
					username: newUsername,
					password: newPassword,
					notes: newNotes,
				}),
			});
			if (!response.ok) {
				throw new Error(data.error || 'Failed to add credential');
			}

			showMessage('Credential added successfully!', 'success');
			addCredentialForm.reset(); // Clear the form
			fetchAndRenderCredentials(); // Refresh the list
		} catch (error) {
			console.error('Error adding credential:', error);
			showMessage(`Error adding credential: ${error.message}`, 'error');
		}
	});
});

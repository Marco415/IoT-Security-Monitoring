/*
 * ============================================================
 * IoT SECURITY MONITORING CLIENT
 * ============================================================
 *
 * Architecture:
 *
 * Browser
 *     |
 *     v
 * API Gateway :8090
 *     |
 *     +---- Auth Service   :8083
 *     |
 *     +---- Device Service :8081
 *     |
 *     +---- Event Service  :8082
 *     |
 *     v
 * Eureka Server :8761
 *
 *
 * The browser ONLY communicates with port 8090.
 */


/* ============================================================
   CONFIGURATION
   ============================================================ */

const API_BASE_URL = "http://localhost:8090";


/* ============================================================
   DOM ELEMENTS
   ============================================================ */

const usernameInput =
    document.getElementById("username");

const passwordInput =
    document.getElementById("password");

const loginButton =
    document.getElementById("loginButton");

const logoutButton =
    document.getElementById("logoutButton");

const registerDeviceButton =
    document.getElementById("registerDeviceButton");

const viewDevicesButton =
    document.getElementById("viewDevicesButton");

const createEventButton =
    document.getElementById("createEventButton");

const viewEventsButton =
    document.getElementById("viewEventsButton");

const devicesContainer =
    document.getElementById("devicesContainer");

const eventsContainer =
    document.getElementById("eventsContainer");

const messageContainer =
    document.getElementById("messageContainer");

const gatewayStatus =
    document.getElementById("gatewayStatus");

const authenticationStatus =
    document.getElementById("authenticationStatus");

const jwtStatus =
    document.getElementById("jwtStatus");


/* ============================================================
   GENERAL FUNCTIONS
   ============================================================ */


/*
 * Display a message.
 */
function showMessage(message, type = "info") {

    messageContainer.innerHTML = `
        <div class="message ${type}">
            ${escapeHtml(message)}
        </div>
    `;
}


/*
 * Escape HTML.
 */
function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


/*
 * Get JWT.
 */
function getJwt() {

    return localStorage.getItem("jwt");
}


/*
 * Save JWT.
 */
function saveJwt(token) {

    localStorage.setItem(
        "jwt",
        token
    );

    updateAuthenticationStatus();
}


/*
 * Remove JWT.
 */
function removeJwt() {

    localStorage.removeItem("jwt");

    updateAuthenticationStatus();
}


/*
 * Update authentication status.
 */
function updateAuthenticationStatus() {

    const token = getJwt();


    if (token) {

        authenticationStatus.textContent =
            "Logged in";

        authenticationStatus.className =
            "status logged-in";


        jwtStatus.textContent =
            "Available";

        jwtStatus.className =
            "status logged-in";

    } else {

        authenticationStatus.textContent =
            "Logged out";

        authenticationStatus.className =
            "status logged-out";


        jwtStatus.textContent =
            "Not available";

        jwtStatus.className =
            "status logged-out";
    }
}


/*
 * Create Authorization header.
 */
function getAuthHeaders() {

    const token = getJwt();


    if (!token) {

        return {};
    }


    return {

        "Authorization":
            `Bearer ${token}`
    };
}


/*
 * Handle HTTP errors.
 */
async function handleResponse(response) {

    if (response.ok) {

        return response;
    }


    let errorMessage =
        `HTTP ${response.status}`;


    try {

        const errorData =
            await response.json();


        if (errorData.message) {

            errorMessage =
                errorData.message;

        } else if (errorData.error) {

            errorMessage =
                errorData.error;
        }

    } catch (error) {

        /*
         * Response was not JSON.
         */
    }


    throw new Error(
        errorMessage
    );
}


/*
 * Parse JSON safely.
 */
async function parseJsonResponse(response) {

    const text =
        await response.text();


    if (!text) {

        return null;
    }


    try {

        return JSON.parse(text);

    } catch (error) {

        return text;
    }
}


/*
 * Convert response into an array.
 *
 * Supports:
 *
 * [
 *   {...},
 *   {...}
 * ]
 *
 * and Spring Page:
 *
 * {
 *   "content": [...]
 * }
 */
function convertToArray(data) {

    if (Array.isArray(data)) {

        return data;
    }


    if (
        data &&
        Array.isArray(data.content)
    ) {

        return data.content;
    }


    if (data) {

        return [data];
    }


    return [];
}


/* ============================================================
   LOGIN
   ============================================================ */


/*
 * POST:
 *
 * http://localhost:8090/api/auth/login
 */
async function login() {

    const username =
        usernameInput.value.trim();

    const password =
        passwordInput.value;


    if (
        !username ||
        !password
    ) {

        showMessage(
            "Please enter a username and password.",
            "error"
        );

        return;
    }


    try {

        showMessage(
            "Logging in...",
            "info"
        );


        const response =
            await fetch(
                `${API_BASE_URL}/api/auth/login`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        username:
                            username,

                        password:
                            password

                    })
                }
            );


        await handleResponse(
            response
        );


        const data =
            await parseJsonResponse(
                response
            );


        /*
         * Accept common JWT response names.
         */
        const token =
            data?.token ||
            data?.jwt ||
            data?.accessToken;


        if (!token) {

            throw new Error(
                "Login succeeded, but no JWT was returned."
            );
        }


        saveJwt(token);


        passwordInput.value = "";


        showMessage(
            "Login successful. JWT stored in localStorage.",
            "success"
        );


    } catch (error) {

        removeJwt();


        showMessage(
            `Login failed: ${error.message}`,
            "error"
        );
    }
}


/*
 * Logout.
 */
function logout() {

    removeJwt();


    showMessage(
        "You have been logged out.",
        "success"
    );
}


/* ============================================================
   DEVICE SERVICE
   ============================================================ */


/*
 * Register a demonstration device.
 *
 * POST:
 *
 * /api/devices
 *
 *
 * Matches Device.java:
 *
 * deviceId
 * name
 * deviceType
 * manufacturer
 * ipAddress
 * location
 * status
 *
 *
 * createdAt and updatedAt are generated
 * by the Java entity.
 */
async function registerDevice() {

    if (!getJwt()) {

        showMessage(
            "Please login before registering a device.",
            "error"
        );

        return;
    }


    const device = {

        deviceId:
            "IOT-001",

        name:
            "Security Camera 001",

        deviceType:
            "CAMERA",

        manufacturer:
            "IoT Security Systems",

        ipAddress:
            "192.168.1.101",

        location:
            "Main Entrance",

        status:
            "ACTIVE"
    };


    try {

        showMessage(
            "Registering demonstration device...",
            "info"
        );


        const response =
            await fetch(
                `${API_BASE_URL}/api/devices`,
                {
                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json",

                        ...getAuthHeaders()
                    },

                    body:
                        JSON.stringify(
                            device
                        )
                }
            );


        await handleResponse(
            response
        );


        const data =
            await parseJsonResponse(
                response
            );


        showMessage(
            "Device registered successfully.",
            "success"
        );


        displaySingleDevice(
            data
        );


    } catch (error) {

        showMessage(
            `Device registration failed: ${error.message}`,
            "error"
        );
    }
}


/*
 * GET:
 *
 * /api/devices
 */
async function viewDevices() {

    if (!getJwt()) {

        showMessage(
            "Please login before viewing devices.",
            "error"
        );

        return;
    }


    try {

        showMessage(
            "Loading devices...",
            "info"
        );


        const response =
            await fetch(
                `${API_BASE_URL}/api/devices`,
                {
                    method: "GET",

                    headers: {
                        ...getAuthHeaders()
                    }
                }
            );


        await handleResponse(
            response
        );


        const data =
            await parseJsonResponse(
                response
            );


        displayDevices(
            data
        );


        showMessage(
            "Devices loaded successfully.",
            "success"
        );


    } catch (error) {

        showMessage(
            `Could not load devices: ${error.message}`,
            "error"
        );
    }
}


/*
 * Display devices.
 */
function displayDevices(data) {

    const devices =
        convertToArray(data);


    if (devices.length === 0) {

        devicesContainer.innerHTML = `
            <p class="placeholder">
                No devices found.
            </p>
        `;

        return;
    }


    let html = `

        <table>

            <thead>

                <tr>

                    <th>Database ID</th>

                    <th>Device ID</th>

                    <th>Name</th>

                    <th>Device Type</th>

                    <th>Manufacturer</th>

                    <th>IP Address</th>

                    <th>Location</th>

                    <th>Status</th>

                </tr>

            </thead>

            <tbody>
    `;


    devices.forEach(
        device => {

            html += `

                <tr>

                    <td>
                        ${escapeHtml(
                            device.id ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            device.deviceId ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            device.name ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            device.deviceType ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            device.manufacturer ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            device.ipAddress ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            device.location ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            device.status ?? ""
                        )}
                    </td>

                </tr>

            `;
        }
    );


    html += `

            </tbody>

        </table>

    `;


    devicesContainer.innerHTML =
        html;
}


/*
 * Display one device.
 */
function displaySingleDevice(device) {

    if (!device) {

        devicesContainer.innerHTML = `

            <p class="placeholder">
                Device was created, but no response
                body was returned.
            </p>

        `;

        return;
    }


    devicesContainer.innerHTML = `

        <table>

            <thead>

                <tr>

                    <th>Property</th>

                    <th>Value</th>

                </tr>

            </thead>


            <tbody>

                <tr>

                    <td>Database ID</td>

                    <td>
                        ${escapeHtml(
                            device.id ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Device ID</td>

                    <td>
                        ${escapeHtml(
                            device.deviceId ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Name</td>

                    <td>
                        ${escapeHtml(
                            device.name ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Device Type</td>

                    <td>
                        ${escapeHtml(
                            device.deviceType ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Manufacturer</td>

                    <td>
                        ${escapeHtml(
                            device.manufacturer ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>IP Address</td>

                    <td>
                        ${escapeHtml(
                            device.ipAddress ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Location</td>

                    <td>
                        ${escapeHtml(
                            device.location ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Status</td>

                    <td>
                        ${escapeHtml(
                            device.status ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Created At</td>

                    <td>
                        ${escapeHtml(
                            device.createdAt ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Updated At</td>

                    <td>
                        ${escapeHtml(
                            device.updatedAt ?? ""
                        )}
                    </td>

                </tr>

            </tbody>

        </table>

    `;
}


/* ============================================================
   SECURITY EVENTS
   ============================================================ */


/*
 * Create security event.
 *
 * POST:
 *
 * /api/events
 *
 *
 * IMPORTANT:
 *
 * SecurityEvent.java currently uses:
 *
 *     Long deviceId
 *
 * Therefore we first retrieve the device and
 * use its database ID.
 */
async function createSecurityEvent() {

    if (!getJwt()) {

        showMessage(
            "Please login before creating a security event.",
            "error"
        );

        return;
    }


    try {

        showMessage(
            "Finding a device for the demonstration event...",
            "info"
        );


        /*
         * Get existing devices.
         */
        const deviceResponse =
            await fetch(
                `${API_BASE_URL}/api/devices`,
                {
                    method: "GET",

                    headers: {
                        ...getAuthHeaders()
                    }
                }
            );


        await handleResponse(
            deviceResponse
        );


        const deviceData =
            await parseJsonResponse(
                deviceResponse
            );


        const devices =
            convertToArray(
                deviceData
            );


        if (devices.length === 0) {

            throw new Error(
                "No devices exist. Click Register Device first."
            );
        }


        /*
         * Prefer IOT-001.
         *
         * Otherwise use the first device.
         */
        const device =
            devices.find(
                item =>
                    item.deviceId === "IOT-001"
            ) || devices[0];


        /*
         * Device.java has:
         *
         * Long id
         */
        if (
            device.id === null ||
            device.id === undefined
        ) {

            throw new Error(
                "The selected device does not have a database ID."
            );
        }


        const numericDeviceId =
            Number(device.id);


        if (
            Number.isNaN(
                numericDeviceId
            )
        ) {

            throw new Error(
                "The device database ID is not numeric."
            );
        }


        /*
         * SecurityEvent.java requires:
         *
         * deviceId
         * eventType
         * severity
         * description
         *
         *
         * eventId is generated by @PrePersist.
         *
         * timestamp is generated by @PrePersist.
         *
         * status is generated by @PrePersist.
         */
        const securityEvent = {

            deviceId:
                numericDeviceId,

            eventType:
                "UNAUTHORIZED_ACCESS",

            severity:
                "HIGH",

            description:
                `Unauthorized access attempt detected on IoT device ${device.deviceId}`,

            sourceIp:
                device.ipAddress ||
                "192.168.1.50"
        };


        showMessage(
            `Creating security event for ${device.deviceId}...`,
            "info"
        );


        /*
         * POST /api/events
         */
        const response =
            await fetch(
                `${API_BASE_URL}/api/events`,
                {
                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json",

                        ...getAuthHeaders()
                    },

                    body:
                        JSON.stringify(
                            securityEvent
                        )
                }
            );


        await handleResponse(
            response
        );


        const data =
            await parseJsonResponse(
                response
            );


        showMessage(
            "Security event created successfully.",
            "success"
        );


        displaySingleEvent(
            data
        );


    } catch (error) {

        showMessage(
            `Security event creation failed: ${error.message}`,
            "error"
        );
    }
}


/*
 * GET:
 *
 * /api/events
 */
async function viewSecurityEvents() {

    if (!getJwt()) {

        showMessage(
            "Please login before viewing security events.",
            "error"
        );

        return;
    }


    try {

        showMessage(
            "Loading security events...",
            "info"
        );


        const response =
            await fetch(
                `${API_BASE_URL}/api/events`,
                {
                    method: "GET",

                    headers: {
                        ...getAuthHeaders()
                    }
                }
            );


        await handleResponse(
            response
        );


        const data =
            await parseJsonResponse(
                response
            );


        displaySecurityEvents(
            data
        );


        showMessage(
            "Security events loaded successfully.",
            "success"
        );


    } catch (error) {

        showMessage(
            `Could not load security events: ${error.message}`,
            "error"
        );
    }
}


/*
 * Display security events.
 */
function displaySecurityEvents(data) {

    const events =
        convertToArray(data);


    if (events.length === 0) {

        eventsContainer.innerHTML = `

            <p class="placeholder">
                No security events found.
            </p>

        `;

        return;
    }


    let html = `

        <table>

            <thead>

                <tr>

                    <th>Database ID</th>

                    <th>Event ID</th>

                    <th>Device ID</th>

                    <th>Event Type</th>

                    <th>Severity</th>

                    <th>Status</th>

                    <th>Source IP</th>

                    <th>Timestamp</th>

                    <th>Description</th>

                </tr>

            </thead>

            <tbody>

    `;


    events.forEach(
        event => {

            const severity =
                String(
                    event.severity ?? ""
                ).toUpperCase();


            let severityClass =
                "badge-low";


            if (
                severity === "HIGH"
            ) {

                severityClass =
                    "badge-high";

            } else if (
                severity === "MEDIUM"
            ) {

                severityClass =
                    "badge-medium";
            }


            html += `

                <tr>

                    <td>
                        ${escapeHtml(
                            event.id ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.eventId ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.deviceId ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.eventType ?? ""
                        )}
                    </td>

                    <td>

                        <span
                            class="badge ${severityClass}"
                        >
                            ${escapeHtml(
                                event.severity ?? ""
                            )}
                        </span>

                    </td>

                    <td>
                        ${escapeHtml(
                            event.status ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.sourceIp ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.timestamp ?? ""
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.description ?? ""
                        )}
                    </td>

                </tr>

            `;
        }
    );


    html += `

            </tbody>

        </table>

    `;


    eventsContainer.innerHTML =
        html;
}


/*
 * Display one security event.
 */
function displaySingleEvent(event) {

    if (!event) {

        eventsContainer.innerHTML = `

            <p class="placeholder">
                Event was created, but no response
                body was returned.
            </p>

        `;

        return;
    }


    eventsContainer.innerHTML = `

        <table>

            <thead>

                <tr>

                    <th>Property</th>

                    <th>Value</th>

                </tr>

            </thead>


            <tbody>

                <tr>

                    <td>Database ID</td>

                    <td>
                        ${escapeHtml(
                            event.id ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Event ID</td>

                    <td>
                        ${escapeHtml(
                            event.eventId ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Device ID</td>

                    <td>
                        ${escapeHtml(
                            event.deviceId ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Event Type</td>

                    <td>
                        ${escapeHtml(
                            event.eventType ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Severity</td>

                    <td>
                        ${escapeHtml(
                            event.severity ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Description</td>

                    <td>
                        ${escapeHtml(
                            event.description ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Source IP</td>

                    <td>
                        ${escapeHtml(
                            event.sourceIp ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Timestamp</td>

                    <td>
                        ${escapeHtml(
                            event.timestamp ?? ""
                        )}
                    </td>

                </tr>


                <tr>

                    <td>Status</td>

                    <td>
                        ${escapeHtml(
                            event.status ?? ""
                        )}
                    </td>

                </tr>

            </tbody>

        </table>

    `;
}


/* ============================================================
   GATEWAY HEALTH
   ============================================================ */


/*
 * Test:
 *
 * GET http://localhost:8090/actuator/health
 */
async function testGateway() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/actuator/health`
            );


        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`
            );
        }


        gatewayStatus.textContent =
            "Online";


        gatewayStatus.className =
            "status success";


    } catch (error) {

        gatewayStatus.textContent =
            "Offline";


        gatewayStatus.className =
            "status error";
    }
}


/* ============================================================
   BUTTON EVENTS
   ============================================================ */

loginButton.addEventListener(
    "click",
    login
);


logoutButton.addEventListener(
    "click",
    logout
);


registerDeviceButton.addEventListener(
    "click",
    registerDevice
);


viewDevicesButton.addEventListener(
    "click",
    viewDevices
);


createEventButton.addEventListener(
    "click",
    createSecurityEvent
);


viewEventsButton.addEventListener(
    "click",
    viewSecurityEvents
);


/* ============================================================
   START CLIENT
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        updateAuthenticationStatus();

        testGateway();

    }
);
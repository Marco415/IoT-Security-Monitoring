/*
 * ============================================================
 * IoT SECURITY MONITORING CLIENT
 * ============================================================
 *
 * Browser
 *    |
 *    v
 * API Gateway :8090
 *    |
 *    +---- Auth Service   :8083
 *    |
 *    +---- Device Service :8081
 *    |
 *    +---- Event Service  :8082
 *    |
 *    v
 * Eureka Server :8761
 *
 *
 * IMPORTANT:
 *
 * The browser ONLY communicates with API Gateway :8090.
 *
 * Device Service:
 *     Device update/delete use database id.
 *
 * Event Service:
 *     Event update/delete use eventId.
 *
 * The Event Service eventId is NOT the same as the
 * database id.
 * ============================================================
 */


/* ============================================================
   CONFIGURATION
   ============================================================ */

const API_BASE_URL =
    "http://localhost:8090";


/* ============================================================
   EVENT ENUMS
   ============================================================ */

const EVENT_TYPES = [

    "UNAUTHORIZED_ACCESS",

    "FAILED_LOGIN",

    "BRUTE_FORCE",

    "MALWARE_DETECTED",

    "SUSPICIOUS_NETWORK_ACTIVITY",

    "PORT_SCAN",

    "DEVICE_OFFLINE",

    "DEVICE_TAMPERING",

    "DATA_EXFILTRATION",

    "ANOMALOUS_BEHAVIOR",

    "POLICY_VIOLATION",

    "OTHER"

];


const EVENT_SEVERITIES = [

    "LOW",

    "MEDIUM",

    "HIGH",

    "CRITICAL"

];


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


const searchDevicesButton =
    document.getElementById("searchDevicesButton");


const clearDeviceSearchButton =
    document.getElementById("clearDeviceSearchButton");


const deviceSearch =
    document.getElementById("deviceSearch");


const devicesContainer =
    document.getElementById("devicesContainer");


const deviceFormContainer =
    document.getElementById("deviceFormContainer");


const deviceFormTitle =
    document.getElementById("deviceFormTitle");


const deviceDatabaseId =
    document.getElementById("deviceDatabaseId");


const deviceIdInput =
    document.getElementById("deviceIdInput");


const deviceNameInput =
    document.getElementById("deviceNameInput");


const deviceTypeInput =
    document.getElementById("deviceTypeInput");


const deviceManufacturerInput =
    document.getElementById("deviceManufacturerInput");


const deviceIpInput =
    document.getElementById("deviceIpInput");


const deviceLocationInput =
    document.getElementById("deviceLocationInput");


const deviceStatusInput =
    document.getElementById("deviceStatusInput");


const saveDeviceButton =
    document.getElementById("saveDeviceButton");


const cancelDeviceButton =
    document.getElementById("cancelDeviceButton");


const createEventButton =
    document.getElementById("createEventButton");


const viewEventsButton =
    document.getElementById("viewEventsButton");


const searchEventsButton =
    document.getElementById("searchEventsButton");


const clearEventSearchButton =
    document.getElementById("clearEventSearchButton");


const eventSearch =
    document.getElementById("eventSearch");


const eventsContainer =
    document.getElementById("eventsContainer");


const eventFormContainer =
    document.getElementById("eventFormContainer");


const eventFormTitle =
    document.getElementById("eventFormTitle");


/*
 * IMPORTANT:
 *
 * eventIdInput stores the Event Service identifier.
 *
 * We deliberately do not use a database-id field for
 * event update/delete operations.
 */

const eventIdInput =
    document.getElementById("eventIdInput");


const eventDeviceInput =
    document.getElementById("eventDeviceInput");


const eventTypeInput =
    document.getElementById("eventTypeInput");


const eventSeverityInput =
    document.getElementById("eventSeverityInput");


const eventSourceIpInput =
    document.getElementById("eventSourceIpInput");


const eventDescriptionInput =
    document.getElementById("eventDescriptionInput");


const eventStatusInput =
    document.getElementById("eventStatusInput");


const saveEventButton =
    document.getElementById("saveEventButton");


const cancelEventButton =
    document.getElementById("cancelEventButton");


const notification =
    document.getElementById("notification");


const notificationIcon =
    document.getElementById("notificationIcon");


const notificationText =
    document.getElementById("notificationText");


const closeNotificationButton =
    document.getElementById("closeNotificationButton");


const messageContainer =
    document.getElementById("messageContainer");


const authenticationStatus =
    document.getElementById("authenticationStatus");


const jwtStatus =
    document.getElementById("jwtStatus");


/* ============================================================
   STATE
   ============================================================ */

let devicesCache = [];

let eventsCache = [];


/* ============================================================
   NOTIFICATIONS
   ============================================================ */

function showNotification(
    message,
    type = "info"
) {

    notification.className =
        `notification ${type}`;


    notificationText.textContent =
        message;


    const icons = {

        success: "✓",

        error: "✕",

        warning: "!",

        info: "●"

    };


    notificationIcon.textContent =
        icons[type] || icons.info;


    notification.scrollIntoView({
        behavior: "smooth",
        block: "nearest"
    });


    showMessage(
        message,
        type
    );
}


function hideNotification() {

    notification.className =
        "notification hidden";
}


function showMessage(
    message,
    type = "info"
) {

    messageContainer.innerHTML = `

        <div class="message ${type}">

            ${escapeHtml(message)}

        </div>

    `;
}


/* ============================================================
   HTML ESCAPING
   ============================================================ */

function escapeHtml(value) {

    if (
        value === null ||
        value === undefined
    ) {

        return "";
    }


    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}


/* ============================================================
   JAVASCRIPT ESCAPING
   ============================================================ */

function escapeJs(
    value
) {

    return String(
        value ?? ""
    )
        .replace(
            /\\/g,
            "\\\\"
        )
        .replace(
            /'/g,
            "\\'"
        )
        .replace(
            /"/g,
            '\\"'
        )
        .replace(
            /\r/g,
            "\\r"
        )
        .replace(
            /\n/g,
            "\\n"
        );
}


/* ============================================================
   JWT
   ============================================================ */

function getJwt() {

    return localStorage.getItem(
        "jwt"
    );
}


function saveJwt(
    token
) {

    localStorage.setItem(
        "jwt",
        token
    );

    updateAuthenticationStatus();
}


function removeJwt() {

    localStorage.removeItem(
        "jwt"
    );

    updateAuthenticationStatus();
}


function updateAuthenticationStatus() {

    const token =
        getJwt();


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


function getAuthHeaders() {

    const token =
        getJwt();


    if (!token) {

        return {};
    }


    return {

        "Authorization":
            `Bearer ${token}`

    };
}


/* ============================================================
   RESPONSE HANDLING
   ============================================================ */

async function handleResponse(
    response
) {

    if (
        response.ok
    ) {

        return response;
    }


    let errorMessage =
        `HTTP ${response.status}`;


    if (
        response.status === 401
    ) {

        removeJwt();

        errorMessage =
            "Authentication failed or the JWT has expired. Please login again.";

    } else if (
        response.status === 403
    ) {

        errorMessage =
            "Access denied. Your account is not authorized for this operation.";

    } else if (
        response.status === 404
    ) {

        errorMessage =
            "The requested resource was not found.";

    } else if (
        response.status === 400
    ) {

        errorMessage =
            "The request was invalid. Check the supplied values.";

    } else if (
        response.status === 503
    ) {

        errorMessage =
            "Service unavailable. The API Gateway could not reach the required microservice.";

    } else if (
        response.status === 502
    ) {

        errorMessage =
            "Bad gateway. The API Gateway could not communicate correctly with the microservice.";

    } else if (
        response.status === 504
    ) {

        errorMessage =
            "Gateway timeout. The microservice did not respond in time.";
    }


    try {

        const clonedResponse =
            response.clone();


        const errorData =
            await clonedResponse.json();


        if (
            errorData.message
        ) {

            errorMessage =
                errorData.message;

        } else if (
            errorData.error
        ) {

            errorMessage =
                errorData.error;

        } else if (
            errorData.detail
        ) {

            errorMessage =
                errorData.detail;

        } else if (
            errorData.errors
        ) {

            errorMessage =
                JSON.stringify(
                    errorData.errors
                );
        }

    } catch (error) {

        try {

            const text =
                await response.text();


            if (
                text
            ) {

                errorMessage =
                    text;
            }

        } catch (ignored) {

            /*
             * No readable response body.
             */
        }
    }


    throw new Error(
        errorMessage
    );
}


async function parseJsonResponse(
    response
) {

    const text =
        await response.text();


    if (!text) {

        return null;
    }


    try {

        return JSON.parse(
            text
        );

    } catch (error) {

        return text;
    }
}


/* ============================================================
   ARRAY CONVERSION
   ============================================================ */

function convertToArray(
    data
) {

    if (
        Array.isArray(data)
    ) {

        return data;
    }


    if (
        data &&
        Array.isArray(
            data.content
        )
    ) {

        return data.content;
    }


    if (
        data &&
        Array.isArray(
            data.items
        )
    ) {

        return data.items;
    }


    if (
        data &&
        Array.isArray(
            data.data
        )
    ) {

        return data.data;
    }


    if (
        data
    ) {

        return [data];
    }


    return [];
}


/* ============================================================
   GENERIC FETCH
   ============================================================ */

async function apiRequest(
    url,
    options = {}
) {

    const requestHeaders = {

        ...(options.body
            ? {
                "Content-Type":
                    "application/json"
            }
            : {}),

        "Accept":
            "application/json",

        ...getAuthHeaders(),

        ...(options.headers || {})

    };


    const response =
        await fetch(
            url,
            {
                ...options,

                headers:
                    requestHeaders
            }
        );


    await handleResponse(
        response
    );


    return parseJsonResponse(
        response
    );
}


/* ============================================================
   LOGIN
   ============================================================ */

async function login() {

    const username =
        usernameInput.value.trim();


    const password =
        passwordInput.value;


    if (
        !username ||
        !password
    ) {

        showNotification(
            "Please enter a username and password.",
            "error"
        );

        return;
    }


    try {

        loginButton.disabled =
            true;


        showNotification(
            "Logging in...",
            "info"
        );


        const response =
            await fetch(
                `${API_BASE_URL}/api/auth/login`,
                {
                    method:
                        "POST",

                    headers: {

                        "Content-Type":
                            "application/json",

                        "Accept":
                            "application/json"

                    },

                    body:
                        JSON.stringify({

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


        const token =
            data?.token ||
            data?.jwt ||
            data?.accessToken;


        if (
            !token
        ) {

            throw new Error(
                "Login succeeded, but no JWT was returned."
            );
        }


        saveJwt(
            token
        );


        passwordInput.value =
            "";


        showNotification(
            "Login successful. Loading dashboard...",
            "success"
        );


        await loadDashboard();


    } catch (error) {

        removeJwt();


        showNotification(
            `Login failed: ${error.message}`,
            "error"
        );

    } finally {

        loginButton.disabled =
            false;
    }
}


/* ============================================================
   LOGOUT
   ============================================================ */

function logout() {

    removeJwt();


    devicesCache =
        [];


    eventsCache =
        [];


    devicesContainer.innerHTML = `

        <p class="placeholder">
            Login to load devices.
        </p>

    `;


    eventsContainer.innerHTML = `

        <p class="placeholder">
            Login to load security events.
        </p>

    `;


    closeDeviceForm();

    closeEventForm();


    deviceSearch.value =
        "";

    eventSearch.value =
        "";


    populateDeviceDropdown();


    showNotification(
        "You have been logged out. Dashboard reset.",
        "success"
    );
}


/* ============================================================
   DASHBOARD LOADING
   ============================================================ */

async function loadDashboard() {

    if (
        !getJwt()
    ) {

        return;
    }


    showNotification(
        "Loading devices and security events...",
        "info"
    );


    const results =
        await Promise.allSettled([

            loadDevices(false),

            loadSecurityEvents(false)

        ]);


    const deviceResult =
        results[0];


    const eventResult =
        results[1];


    if (
        deviceResult.status === "fulfilled" &&
        eventResult.status === "fulfilled"
    ) {

        showNotification(
            "Dashboard loaded successfully.",
            "success"
        );

    } else if (
        deviceResult.status === "fulfilled"
    ) {

        showNotification(
            "Devices loaded, but security events could not be loaded.",
            "warning"
        );

    } else if (
        eventResult.status === "fulfilled"
    ) {

        showNotification(
            "Security events loaded, but devices could not be loaded.",
            "warning"
        );

    } else {

        showNotification(
            "The dashboard could not load the required services.",
            "error"
        );
    }
}


/* ============================================================
   DEVICE FORM
   ============================================================ */

function openDeviceCreateForm() {

    clearDeviceForm();


    deviceFormTitle.textContent =
        "Register Device";


    saveDeviceButton.textContent =
        "Register Device";


    deviceFormContainer.classList.remove(
        "hidden"
    );


    deviceFormContainer.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


function openDeviceEditForm(
    id
) {

    const device =
        devicesCache.find(
            item =>
                String(
                    item.id
                ) ===
                String(id)
        );


    if (!device) {

        showNotification(
            "The selected device could not be found.",
            "error"
        );

        return;
    }


    deviceFormTitle.textContent =
        "Edit Device";


    saveDeviceButton.textContent =
        "Update Device";


    deviceDatabaseId.value =
        device.id ?? "";


    deviceIdInput.value =
        device.deviceId ?? "";


    deviceNameInput.value =
        device.name ?? "";


    deviceTypeInput.value =
        device.deviceType ?? "";


    deviceManufacturerInput.value =
        device.manufacturer ?? "";


    deviceIpInput.value =
        device.ipAddress ?? "";


    deviceLocationInput.value =
        device.location ?? "";


    deviceStatusInput.value =
        device.status ?? "ACTIVE";


    deviceFormContainer.classList.remove(
        "hidden"
    );


    deviceFormContainer.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


function clearDeviceForm() {

    deviceDatabaseId.value =
        "";

    deviceIdInput.value =
        "";

    deviceNameInput.value =
        "";

    deviceTypeInput.value =
        "";

    deviceManufacturerInput.value =
        "";

    deviceIpInput.value =
        "";

    deviceLocationInput.value =
        "";

    deviceStatusInput.value =
        "ACTIVE";
}


function closeDeviceForm() {

    deviceFormContainer.classList.add(
        "hidden"
    );

    clearDeviceForm();
}


/* ============================================================
   DEVICE CREATE / UPDATE
   ============================================================ */

async function saveDevice() {

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before saving a device.",
            "error"
        );

        return;
    }


    const deviceId =
        deviceIdInput.value.trim();


    const name =
        deviceNameInput.value.trim();


    const deviceType =
        deviceTypeInput.value.trim();


    if (
        !deviceId ||
        !name ||
        !deviceType
    ) {

        showNotification(
            "Device ID, name and device type are required.",
            "error"
        );

        return;
    }


    const device = {

        deviceId:
            deviceId,

        name:
            name,

        deviceType:
            deviceType,

        manufacturer:
            deviceManufacturerInput.value.trim(),

        ipAddress:
            deviceIpInput.value.trim(),

        location:
            deviceLocationInput.value.trim(),

        status:
            deviceStatusInput.value

    };


    const id =
        deviceDatabaseId.value.trim();


    const isUpdate =
        Boolean(id);


    try {

        saveDeviceButton.disabled =
            true;


        showNotification(
            isUpdate
                ? "Updating device..."
                : "Registering device...",
            "info"
        );


        const url =
            isUpdate

                ? `${API_BASE_URL}/api/devices/${encodeURIComponent(id)}`

                : `${API_BASE_URL}/api/devices`;


        const method =
            isUpdate
                ? "PUT"
                : "POST";


        await apiRequest(
            url,
            {
                method:
                    method,

                body:
                    JSON.stringify(
                        device
                    )
            }
        );


        closeDeviceForm();


        showNotification(
            isUpdate
                ? "Device updated successfully."
                : "Device registered successfully.",
            "success"
        );


        await loadDevices(
            false
        );


    } catch (error) {

        showNotification(
            `Device ${isUpdate ? "update" : "registration"} failed: ${error.message}`,
            "error"
        );

    } finally {

        saveDeviceButton.disabled =
            false;
    }
}


/* ============================================================
   DEVICE DELETE
   ============================================================ */

async function deleteDevice(
    id
) {

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before deleting a device.",
            "error"
        );

        return;
    }


    const device =
        devicesCache.find(
            item =>
                String(
                    item.id
                ) ===
                String(id)
        );


    if (!device) {

        showNotification(
            "The selected device could not be found.",
            "error"
        );

        return;
    }


    const confirmed =
        confirm(
            `Delete device "${device.name || device.deviceId}"?\n\nThis action cannot be undone.`
        );


    if (
        !confirmed
    ) {

        return;
    }


    try {

        showNotification(
            "Deleting device...",
            "info"
        );


        await apiRequest(
            `${API_BASE_URL}/api/devices/${encodeURIComponent(id)}`,
            {
                method:
                    "DELETE"
            }
        );


        showNotification(
            "Device deleted successfully.",
            "success"
        );


        await loadDevices(
            false
        );


    } catch (error) {

        showNotification(
            `Device deletion failed: ${error.message}`,
            "error"
        );
    }
}


/* ============================================================
   DEVICE VIEWING
   ============================================================ */

async function loadDevices(
    showNotificationMessage = true
) {

    if (
        !getJwt()
    ) {

        throw new Error(
            "Please login before viewing devices."
        );
    }


    if (
        showNotificationMessage
    ) {

        showNotification(
            "Loading devices...",
            "info"
        );
    }


    try {

        const data =
            await apiRequest(
                `${API_BASE_URL}/api/devices`,
                {
                    method:
                        "GET"
                }
            );


        devicesCache =
            convertToArray(
                data
            );


        displayDevices(
            devicesCache
        );


        populateDeviceDropdown();


        if (
            showNotificationMessage
        ) {

            showNotification(
                "Devices loaded successfully.",
                "success"
            );
        }


        return devicesCache;


    } catch (error) {

        devicesContainer.innerHTML = `

            <p class="placeholder">
                Could not load devices.
            </p>

        `;


        if (
            showNotificationMessage
        ) {

            showNotification(
                `Could not load devices: ${error.message}`,
                "error"
            );
        }


        throw error;
    }
}


async function viewDevices() {

    try {

        await loadDevices(
            true
        );

    } catch (error) {

        /*
         * Error already displayed.
         */
    }
}


/* ============================================================
   DEVICE SEARCH
   ============================================================ */

function searchDevices() {

    const search =
        deviceSearch.value
            .trim()
            .toLowerCase();


    if (
        !search
    ) {

        displayDevices(
            devicesCache
        );


        showNotification(
            "Showing all devices.",
            "info"
        );

        return;
    }


    const filtered =
        devicesCache.filter(
            device => {

                const values = [

                    device.id,

                    device.deviceId,

                    device.name,

                    device.deviceType,

                    device.manufacturer,

                    device.ipAddress,

                    device.location,

                    device.status

                ];


                return values.some(
                    value =>
                        String(
                            value ?? ""
                        )
                            .toLowerCase()
                            .includes(
                                search
                            )
                );

            }
        );


    displayDevices(
        filtered
    );


    showNotification(
        `${filtered.length} device(s) matched "${deviceSearch.value.trim()}".`,
        "info"
    );
}


function clearDeviceSearch() {

    deviceSearch.value =
        "";


    displayDevices(
        devicesCache
    );


    showNotification(
        "Device search cleared.",
        "info"
    );
}


/* ============================================================
   DISPLAY DEVICES
   ============================================================ */

function displayDevices(
    data
) {

    const devices =
        Array.isArray(data)
            ? data
            : convertToArray(data);


    if (
        devices.length === 0
    ) {

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

                    <th>Actions</th>

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

                    <td class="actions-cell">

                        <button
                            type="button"
                            class="small-button edit-button"
                            onclick="openDeviceEditForm('${escapeJs(device.id)}')"
                        >
                            Edit
                        </button>


                        <button
                            type="button"
                            class="small-button delete-button"
                            onclick="deleteDevice('${escapeJs(device.id)}')"
                        >
                            Delete
                        </button>

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


function displaySingleDevice(
    device
) {

    if (
        !device
    ) {

        devicesContainer.innerHTML = `

            <p class="placeholder">
                Device was created, but no response
                body was returned.
            </p>

        `;

        return;
    }


    displayDevices(
        [device]
    );
}


/* ============================================================
   EVENT FORM
   ============================================================ */

async function openEventCreateForm() {

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before creating a security event.",
            "error"
        );

        return;
    }


    try {

        if (
            devicesCache.length === 0
        ) {

            await loadDevices(
                false
            );
        }


        if (
            devicesCache.length === 0
        ) {

            throw new Error(
                "No devices exist. Register a device before creating an event."
            );
        }


        clearEventForm();


        eventFormTitle.textContent =
            "Create Security Event";


        saveEventButton.textContent =
            "Create Event";


        populateDeviceDropdown();


        eventFormContainer.classList.remove(
            "hidden"
        );


        eventFormContainer.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });


    } catch (error) {

        showNotification(
            error.message,
            "error"
        );
    }
}


/* ============================================================
   EVENT EDIT
   ============================================================ */

/*
 * IMPORTANT BACKEND CHANGE
 *
 * Event Service retrieves a specific event by eventId.
 *
 * Therefore:
 *
 *     openEventEditForm(eventId)
 *
 * searches eventsCache by event.eventId.
 *
 * It does NOT search by event.id.
 */

function openEventEditForm(
    eventId
) {

    const event =
        eventsCache.find(
            item =>
                String(
                    item.eventId
                ) ===
                String(eventId)
        );


    if (
        !event
    ) {

        showNotification(
            "The selected security event could not be found.",
            "error"
        );

        return;
    }


    /*
     * eventId is the actual identifier required by
     * the Event Service endpoint.
     */

    const identifier =
        event.eventId;


    if (
        !identifier
    ) {

        showNotification(
            "The selected event does not contain an eventId.",
            "error"
        );

        return;
    }


    eventFormTitle.textContent =
        "Edit Security Event";


    saveEventButton.textContent =
        "Update Event";


    eventIdInput.value =
        identifier;


    populateDeviceDropdown();


    /*
     * The Event Service stores deviceId.
     *
     * The device dropdown uses the device database ID.
     */

    eventDeviceInput.value =
        event.deviceId !== null &&
        event.deviceId !== undefined
            ? String(event.deviceId)
            : "";


    eventTypeInput.value =
        event.eventType ?? "";


    eventSeverityInput.value =
        event.severity ?? "";


    eventSourceIpInput.value =
        event.sourceIp ?? "";


    eventDescriptionInput.value =
        event.description ?? "";


    eventStatusInput.value =
        event.status ?? "OPEN";


    eventFormContainer.classList.remove(
        "hidden"
    );


    eventFormContainer.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


function clearEventForm() {

    eventIdInput.value =
        "";

    eventDeviceInput.value =
        "";

    eventTypeInput.value =
        "";

    eventSeverityInput.value =
        "";

    eventSourceIpInput.value =
        "";

    eventDescriptionInput.value =
        "";

    eventStatusInput.value =
        "OPEN";
}


function closeEventForm() {

    eventFormContainer.classList.add(
        "hidden"
    );

    clearEventForm();
}


/* ============================================================
   DEVICE DROPDOWN
   ============================================================ */

function populateDeviceDropdown() {

    eventDeviceInput.innerHTML = `

        <option value="">
            Select a device
        </option>

    `;


    devicesCache.forEach(
        device => {

            if (
                device.id === null ||
                device.id === undefined
            ) {

                return;
            }


            const option =
                document.createElement(
                    "option"
                );


            option.value =
                String(
                    device.id
                );


            option.textContent =
                `${device.deviceId || "Unknown"} - ${device.name || "Unnamed device"}`;


            eventDeviceInput.appendChild(
                option
            );
        }
    );
}


/* ============================================================
   EVENT ENUM VALIDATION
   ============================================================ */

function isValidEventType(
    eventType
) {

    return EVENT_TYPES.includes(
        eventType
    );
}


function isValidSeverity(
    severity
) {

    return EVENT_SEVERITIES.includes(
        severity
    );
}


/* ============================================================
   EVENT CREATE / UPDATE
   ============================================================ */

async function saveEvent() {

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before saving a security event.",
            "error"
        );

        return;
    }


    const selectedDeviceId =
        eventDeviceInput.value;


    const eventType =
        eventTypeInput.value;


    const severity =
        eventSeverityInput.value;


    const sourceIp =
        eventSourceIpInput.value.trim();


    const description =
        eventDescriptionInput.value.trim();


    if (
        !selectedDeviceId ||
        !eventType ||
        !severity ||
        !description
    ) {

        showNotification(
            "Device, event type, severity and description are required.",
            "error"
        );

        return;
    }


    /*
     * Validate against the exact Java EventType enum.
     */

    if (
        !isValidEventType(
            eventType
        )
    ) {

        showNotification(
            `Invalid event type: ${eventType}`,
            "error"
        );

        return;
    }


    /*
     * Validate against the exact Java Severity enum.
     */

    if (
        !isValidSeverity(
            severity
        )
    ) {

        showNotification(
            `Invalid severity: ${severity}`,
            "error"
        );

        return;
    }


    const numericDeviceId =
        Number(
            selectedDeviceId
        );


    if (
        !Number.isInteger(
            numericDeviceId
        ) ||
        numericDeviceId <= 0
    ) {

        showNotification(
            "The selected device database ID is invalid.",
            "error"
        );

        return;
    }


    /*
     * IMPORTANT:
     *
     * eventId is the Event Service identifier.
     *
     * Empty eventId = CREATE
     *
     * Existing eventId = UPDATE
     */

    const eventId =
        eventIdInput.value.trim();


    const isUpdate =
        Boolean(eventId);


    /*
     * Request body.
     *
     * eventId is deliberately not sent during CREATE.
     *
     * The backend generates the eventId.
     */

    const securityEvent = {

        deviceId:
            numericDeviceId,

        eventType:
            eventType,

        severity:
            severity,

        description:
            description,

        sourceIp:
            sourceIp

    };


    /*
     * Status is included for UPDATE.
     *
     * This retains the existing event status feature.
     */

    if (
        isUpdate &&
        eventStatusInput.value
    ) {

        securityEvent.status =
            eventStatusInput.value;
    }


    try {

        saveEventButton.disabled =
            true;


        showNotification(
            isUpdate
                ? "Updating security event..."
                : "Creating security event...",
            "info"
        );


        /*
         * CREATE:
         *
         * POST /api/events
         *
         *
         * UPDATE:
         *
         * PUT /api/events/{eventId}
         *
         * NOT:
         *
         * PUT /api/events/{databaseId}
         */

        const url =
            isUpdate

                ? `${API_BASE_URL}/api/events/${encodeURIComponent(eventId)}`

                : `${API_BASE_URL}/api/events`;


        const method =
            isUpdate
                ? "PUT"
                : "POST";


        await apiRequest(
            url,
            {
                method:
                    method,

                body:
                    JSON.stringify(
                        securityEvent
                    )
            }
        );


        closeEventForm();


        showNotification(
            isUpdate
                ? "Security event updated successfully."
                : "Security event created successfully.",
            "success"
        );


        await loadSecurityEvents(
            false
        );


    } catch (error) {

        const message =
            error.message.toLowerCase();


        if (
            message.includes(
                "service unavailable"
            )
        ) {

            showNotification(
                "Event Service is unavailable through the API Gateway. Check that the Event Service is running and registered with Eureka.",
                "error"
            );

        } else {

            showNotification(
                `Security event ${isUpdate ? "update" : "creation"} failed: ${error.message}`,
                "error"
            );
        }

    } finally {

        saveEventButton.disabled =
            false;
    }
}


/* ============================================================
   EVENT DELETE
   ============================================================ */

/*
 * IMPORTANT:
 *
 * The parameter here is eventId.
 *
 * The database id is NOT used for DELETE.
 */

async function deleteEvent(
    eventId
) {

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before deleting an event.",
            "error"
        );

        return;
    }


    const event =
        eventsCache.find(
            item =>
                String(
                    item.eventId
                ) ===
                String(eventId)
        );


    if (
        !event
    ) {

        showNotification(
            "The selected security event could not be found.",
            "error"
        );

        return;
    }


    if (
        !event.eventId
    ) {

        showNotification(
            "The selected security event does not contain an eventId.",
            "error"
        );

        return;
    }


    const eventName =
        event.eventId;


    const confirmed =
        confirm(
            `Delete security event "${eventName}"?\n\nThis action cannot be undone.`
        );


    if (
        !confirmed
    ) {

        return;
    }


    try {

        showNotification(
            "Deleting security event...",
            "info"
        );


        /*
         * IMPORTANT:
         *
         * DELETE uses eventId.
         */

        await apiRequest(
            `${API_BASE_URL}/api/events/${encodeURIComponent(event.eventId)}`,
            {
                method:
                    "DELETE"
            }
        );


        showNotification(
            "Security event deleted successfully.",
            "success"
        );


        await loadSecurityEvents(
            false
        );


    } catch (error) {

        showNotification(
            `Security event deletion failed: ${error.message}`,
            "error"
        );
    }
}


/* ============================================================
   EVENT VIEWING
   ============================================================ */

async function loadSecurityEvents(
    showNotificationMessage = true
) {

    if (
        !getJwt()
    ) {

        throw new Error(
            "Please login before viewing security events."
        );
    }


    if (
        showNotificationMessage
    ) {

        showNotification(
            "Loading security events...",
            "info"
        );
    }


    try {

        const data =
            await apiRequest(
                `${API_BASE_URL}/api/events`,
                {
                    method:
                        "GET"
                }
            );


        eventsCache =
            convertToArray(
                data
            );


        displaySecurityEvents(
            eventsCache
        );


        if (
            showNotificationMessage
        ) {

            showNotification(
                "Security events loaded successfully.",
                "success"
            );
        }


        return eventsCache;


    } catch (error) {

        eventsContainer.innerHTML = `

            <p class="placeholder">
                Security events could not be loaded.
            </p>

        `;


        if (
            showNotificationMessage
        ) {

            showNotification(
                `Could not load security events: ${error.message}`,
                "error"
            );
        }


        throw error;
    }
}


async function viewSecurityEvents() {

    try {

        await loadSecurityEvents(
            true
        );

    } catch (error) {

        /*
         * Error already displayed.
         */
    }
}


/* ============================================================
   EVENT SEARCH
   ============================================================ */

function searchEvents() {

    const search =
        eventSearch.value
            .trim()
            .toLowerCase();


    if (
        !search
    ) {

        displaySecurityEvents(
            eventsCache
        );


        showNotification(
            "Event search cleared. Showing all events.",
            "info"
        );

        return;
    }


    const filtered =
        eventsCache.filter(
            event => {

                const values = [

                    /*
                     * Keep both identifiers searchable.
                     */

                    event.id,

                    event.eventId,

                    event.deviceId,

                    event.eventType,

                    event.severity,

                    event.status,

                    event.sourceIp,

                    event.timestamp,

                    event.description

                ];


                return values.some(
                    value =>
                        String(
                            value ?? ""
                        )
                            .toLowerCase()
                            .includes(
                                search
                            )
                );

            }
        );


    displaySecurityEvents(
        filtered
    );


    showNotification(
        `${filtered.length} event(s) matched "${eventSearch.value.trim()}".`,
        "info"
    );
}


function clearEventSearch() {

    eventSearch.value =
        "";


    displaySecurityEvents(
        eventsCache
    );


    showNotification(
        "Event search cleared.",
        "info"
    );
}


/* ============================================================
   EVENT STATUS DISPLAY
   ============================================================ */

function getEventStatusClass(
    status
) {

    switch (
        String(
            status ?? ""
        ).toUpperCase()
    ) {

        case "OPEN":

            return "event-status-open";


        case "INVESTIGATING":

            return "event-status-investigating";


        case "RESOLVED":

            return "event-status-resolved";


        case "CLOSED":

            return "event-status-closed";


        default:

            return "";
    }
}


/* ============================================================
   DISPLAY EVENTS
   ============================================================ */

function displaySecurityEvents(
    data
) {

    const events =
        Array.isArray(data)
            ? data
            : convertToArray(data);


    if (
        events.length === 0
    ) {

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

                    <th>Actions</th>

                </tr>

            </thead>

            <tbody>

    `;


    events.forEach(
        event => {

            const severity =
                String(
                    event.severity ?? ""
                )
                    .toUpperCase();


            let severityClass =
                "badge-low";


            if (
                severity ===
                "CRITICAL"
            ) {

                severityClass =
                    "badge-critical";

            } else if (
                severity ===
                "HIGH"
            ) {

                severityClass =
                    "badge-high";

            } else if (
                severity ===
                "MEDIUM"
            ) {

                severityClass =
                    "badge-medium";
            }


            const status =
                String(
                    event.status ?? ""
                )
                    .toUpperCase();


            const statusClass =
                getEventStatusClass(
                    status
                );


            /*
             * The buttons use event.eventId.
             *
             * This is the critical fix.
             */

            const eventIdentifier =
                event.eventId ?? "";


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

                        <span
                            class="event-status ${statusClass}"
                        >
                            ${escapeHtml(
                                event.status ?? ""
                            )}
                        </span>

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

                    <td class="actions-cell">

                        <button
                            type="button"
                            class="small-button edit-button"
                            onclick="openEventEditForm('${escapeJs(eventIdentifier)}')"
                            ${eventIdentifier ? "" : "disabled"}
                        >
                            Edit
                        </button>


                        <button
                            type="button"
                            class="small-button delete-button"
                            onclick="deleteEvent('${escapeJs(eventIdentifier)}')"
                            ${eventIdentifier ? "" : "disabled"}
                        >
                            Delete
                        </button>

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


/* ============================================================
   DISPLAY SINGLE EVENT
   ============================================================ */

function displaySingleEvent(
    event
) {

    if (
        !event
    ) {

        eventsContainer.innerHTML = `

            <p class="placeholder">
                Event was created, but no response
                body was returned.
            </p>

        `;

        return;
    }


    displaySecurityEvents(
        [event]
    );
}


/* ============================================================
   EVENT BUTTONS
   ============================================================ */

registerDeviceButton.addEventListener(
    "click",
    openDeviceCreateForm
);


viewDevicesButton.addEventListener(
    "click",
    viewDevices
);


searchDevicesButton.addEventListener(
    "click",
    searchDevices
);


clearDeviceSearchButton.addEventListener(
    "click",
    clearDeviceSearch
);


saveDeviceButton.addEventListener(
    "click",
    saveDevice
);


cancelDeviceButton.addEventListener(
    "click",
    closeDeviceForm
);


createEventButton.addEventListener(
    "click",
    openEventCreateForm
);


viewEventsButton.addEventListener(
    "click",
    viewSecurityEvents
);


searchEventsButton.addEventListener(
    "click",
    searchEvents
);


clearEventSearchButton.addEventListener(
    "click",
    clearEventSearch
);


saveEventButton.addEventListener(
    "click",
    saveEvent
);


cancelEventButton.addEventListener(
    "click",
    closeEventForm
);


loginButton.addEventListener(
    "click",
    login
);


logoutButton.addEventListener(
    "click",
    logout
);


closeNotificationButton.addEventListener(
    "click",
    hideNotification
);


/* ============================================================
   ENTER KEY SUPPORT
   ============================================================ */

usernameInput.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            login();
        }
    }
);


passwordInput.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            login();
        }
    }
);


deviceSearch.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            searchDevices();
        }
    }
);


eventSearch.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            searchEvents();
        }
    }
);


/* ============================================================
   START CLIENT
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        updateAuthenticationStatus();


        /*
         * Restore an existing JWT session.
         */

        if (
            getJwt()
        ) {

            loadDashboard()
                .catch(
                    error => {

                        showNotification(
                            `Dashboard loading failed: ${error.message}`,
                            "error"
                        );

                    }
                );
        }

    }
);
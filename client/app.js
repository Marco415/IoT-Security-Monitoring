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
 * ============================================================
 */


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


const EVENT_STATUSES = [

    "OPEN",
    "INVESTIGATING",
    "RESOLVED",
    "CLOSED"

];


const USER_ROLES = [

    "USER",
    "ADMIN"

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


/* ============================================================
   USER REGISTRATION ELEMENTS
   ============================================================ */

const userRegistrationCard =
    document.getElementById("userRegistrationCard");


const registerUsernameInput =
    document.getElementById(
        "registerUsernameInput"
    );


const registerPasswordInput =
    document.getElementById(
        "registerPasswordInput"
    );


const registerRoleInput =
    document.getElementById(
        "registerRoleInput"
    );


const registerUserButton =
    document.getElementById(
        "registerUserButton"
    );


const clearRegistrationButton =
    document.getElementById(
        "clearRegistrationButton"
    );


/* ============================================================
   DEVICE ELEMENTS
   ============================================================ */

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


/* ============================================================
   EVENT ELEMENTS
   ============================================================ */

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


/* ============================================================
   NOTIFICATION ELEMENTS
   ============================================================ */

const notification =
    document.getElementById("notification");


const notificationIcon =
    document.getElementById("notificationIcon");


const notificationText =
    document.getElementById("notificationText");


const closeNotificationButton =
    document.getElementById(
        "closeNotificationButton"
    );


const messageContainer =
    document.getElementById("messageContainer");


/* ============================================================
   SESSION STATUS ELEMENTS
   ============================================================ */

const authenticationStatus =
    document.getElementById(
        "authenticationStatus"
    );


const currentUsername =
    document.getElementById(
        "currentUsername"
    );


const currentUserRole =
    document.getElementById(
        "currentUserRole"
    );


const jwtStatus =
    document.getElementById(
        "jwtStatus"
    );


/* ============================================================
   STATE
   ============================================================ */

let devicesCache = [];

let eventsCache = [];

let notificationTimeout = null;


/* ============================================================
   STORAGE KEYS
   ============================================================ */

const STORAGE_KEYS = {

    jwt:
        "jwt",

    username:
        "username",

    role:
        "role"

};


/* ============================================================
   NOTIFICATIONS
   ============================================================ */

function showNotification(
    message,
    type = "info"
) {

    clearNotificationTimer();


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


    if (
        type !== "error"
    ) {

        notificationTimeout =
            setTimeout(
                () => {

                    hideNotification();

                },
                4500
            );

    }
}


function hideNotification() {

    clearNotificationTimer();


    notification.className =
        "notification hidden";
}


function clearNotificationTimer() {

    if (
        notificationTimeout
    ) {

        clearTimeout(
            notificationTimeout
        );

        notificationTimeout =
            null;
    }
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


    if (
        type !== "error"
    ) {

        setTimeout(
            () => {

                messageContainer.innerHTML =
                    "";

            },
            4500
        );
    }
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

function escapeJs(value) {

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
   JWT / SESSION
   ============================================================ */

function getJwt() {

    return localStorage.getItem(
        STORAGE_KEYS.jwt
    );
}


function saveJwt(token) {

    localStorage.setItem(
        STORAGE_KEYS.jwt,
        token
    );

    updateAuthenticationStatus();
}


function removeJwt() {

    localStorage.removeItem(
        STORAGE_KEYS.jwt
    );

    updateAuthenticationStatus();
}


function getUsername() {

    return localStorage.getItem(
        STORAGE_KEYS.username
    ) || "";
}


function saveUsername(username) {

    localStorage.setItem(
        STORAGE_KEYS.username,
        username
    );
}


function removeUsername() {

    localStorage.removeItem(
        STORAGE_KEYS.username
    );
}


function getRole() {

    return (
        localStorage.getItem(
            STORAGE_KEYS.role
        ) || ""
    ).toUpperCase();
}


function saveRole(role) {

    localStorage.setItem(
        STORAGE_KEYS.role,
        String(
            role || ""
        ).toUpperCase()
    );
}


function removeRole() {

    localStorage.removeItem(
        STORAGE_KEYS.role
    );
}


/* ============================================================
   ADMIN CHECK
   ============================================================ */

function isAdmin() {

    return (
        getRole() ===
        "ADMIN"
    );
}


/* ============================================================
   REGISTRATION VISIBILITY
   ============================================================ */

function updateRegistrationVisibility() {

    if (
        getJwt() &&
        isAdmin()
    ) {

        userRegistrationCard.classList.remove(
            "hidden"
        );

    } else {

        userRegistrationCard.classList.add(
            "hidden"
        );

        clearRegistrationForm();
    }
}


/* ============================================================
   AUTHENTICATION STATUS
   ============================================================ */

function updateAuthenticationStatus() {

    const token =
        getJwt();


    if (
        token
    ) {

        authenticationStatus.textContent =
            "Logged in";

        authenticationStatus.className =
            "status logged-in";


        jwtStatus.textContent =
            "Available";

        jwtStatus.className =
            "status logged-in";


        currentUsername.textContent =
            getUsername() ||
            "Unknown";


        currentUsername.className =
            "status logged-in";


        currentUserRole.textContent =
            getRole() ||
            "Unknown";


        currentUserRole.className =
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


        currentUsername.textContent =
            "Not logged in";

        currentUsername.className =
            "status logged-out";


        currentUserRole.textContent =
            "Not available";

        currentUserRole.className =
            "status logged-out";
    }


    updateRegistrationVisibility();
}


/* ============================================================
   CLEAR COMPLETE SESSION
   ============================================================ */

function clearSession() {

    removeJwt();

    removeUsername();

    removeRole();

    usernameInput.value =
        "";

    passwordInput.value =
        "";
}


/* ============================================================
   AUTH HEADERS
   ============================================================ */

function getAuthHeaders() {

    const token =
        getJwt();


    if (
        !token
    ) {

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
        response.status === 409
    ) {

        errorMessage =
            "The requested account or resource already exists.";

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


    if (
        !text
    ) {

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
   GENERIC API REQUEST
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


        const returnedUsername =
            data?.username ||
            username;


        const returnedRole =
            String(
                data?.role ||
                "USER"
            ).toUpperCase();


        if (
            !USER_ROLES.includes(
                returnedRole
            )
        ) {

            throw new Error(
                "Login succeeded, but the server returned an invalid user role."
            );
        }


        saveJwt(
            token
        );


        saveUsername(
            returnedUsername
        );


        saveRole(
            returnedRole
        );


        passwordInput.value =
            "";


        updateAuthenticationStatus();


        showNotification(
            `Login successful. Welcome ${returnedUsername}. Loading dashboard...`,
            "success"
        );


        await loadDashboard();


    } catch (error) {

        clearSession();


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
   LOGOUT / COMPLETE DASHBOARD RESET
   ============================================================ */

function logout() {

    clearSession();


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


    clearRegistrationForm();


    populateDeviceDropdown();


    updateAuthenticationStatus();


    messageContainer.innerHTML =
        "";


    showNotification(
        "You have been logged out. The dashboard has been completely reset.",
        "success"
    );
}


/* ============================================================
   USER REGISTRATION
   ============================================================ */

function clearRegistrationForm() {

    if (
        registerUsernameInput
    ) {

        registerUsernameInput.value =
            "";
    }


    if (
        registerPasswordInput
    ) {

        registerPasswordInput.value =
            "";
    }


    if (
        registerRoleInput
    ) {

        registerRoleInput.value =
            "USER";
    }
}


async function registerUser() {

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before registering a user.",
            "error"
        );

        return;
    }


    if (
        !isAdmin()
    ) {

        showNotification(
            "Access denied. Only administrators can register new users.",
            "error"
        );

        updateRegistrationVisibility();

        return;
    }


    const username =
        registerUsernameInput.value.trim();


    const password =
        registerPasswordInput.value;


    const role =
        registerRoleInput.value.trim().toUpperCase();


    if (
        !username ||
        !password ||
        !role
    ) {

        showNotification(
            "Username, password and role are required.",
            "error"
        );

        return;
    }


    if (
        !USER_ROLES.includes(
            role
        )
    ) {

        showNotification(
            "Invalid role. Select USER or ADMIN.",
            "error"
        );

        return;
    }


    if (
        username.length < 3
    ) {

        showNotification(
            "Username must contain at least 3 characters.",
            "error"
        );

        return;
    }


    if (
        password.length < 6
    ) {

        showNotification(
            "Password must contain at least 6 characters.",
            "error"
        );

        return;
    }


    try {

        registerUserButton.disabled =
            true;


        showNotification(
            "Registering new user...",
            "info"
        );


        await apiRequest(
            `${API_BASE_URL}/api/auth/register`,
            {
                method:
                    "POST",

                body:
                    JSON.stringify({

                        username:
                            username,

                        password:
                            password,

                        role:
                            role

                    })
            }
        );


        clearRegistrationForm();


        showNotification(
            `User "${username}" registered successfully with role ${role}.`,
            "success"
        );


    } catch (error) {

        if (
            error.message
                .toLowerCase()
                .includes(
                    "access denied"
                )
        ) {

            showNotification(
                "Access denied. Only administrators can register new users.",
                "error"
            );

        } else {

            showNotification(
                `User registration failed: ${error.message}`,
                "error"
            );
        }

    } finally {

        registerUserButton.disabled =
            false;
    }
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


    updateAuthenticationStatus();


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

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before registering a device.",
            "error"
        );

        return;
    }


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


    if (
        !device
    ) {

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


        await loadDevices(false);


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


    if (
        !device
    ) {

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


        await loadDevices(false);


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

        await loadDevices(true);

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

            await loadDevices(false);
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


        /*
         * Make the default status explicit.
         *
         * This is important because the selected value
         * will now also be sent to the backend when creating
         * a new event.
         */

        eventStatusInput.value =
            "OPEN";


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
   FIND DEVICE FOR EVENT
   ============================================================
 *
 * The Event Service may return deviceId as:
 *
 * 1. Device database ID:
 *       5
 *
 * 2. Device's external deviceId:
 *       "IOT-001"
 *
 * 3. A nested device object:
 *       {
 *           id: 5,
 *           deviceId: "IOT-001"
 *       }
 *
 * The event form dropdown uses the database ID as its
 * option value, so this function resolves all supported
 * representations to the correct database ID.
 *
 * ============================================================ */

function findDeviceForEvent(
    event
) {

    if (
        !event
    ) {

        return null;
    }


    const eventDevice =
        event.device ||
        event.deviceEntity ||
        null;


    const possibleIdentifiers = [

        event.deviceId,

        event.deviceID,

        event.device_id,

        eventDevice?.id,

        eventDevice?.deviceId,

        eventDevice?.deviceID,

        eventDevice?.device_id

    ]
        .filter(
            value =>
                value !== null &&
                value !== undefined &&
                String(value).trim() !== ""
        )
        .map(
            value =>
                String(value).trim()
        );


    if (
        possibleIdentifiers.length === 0
    ) {

        return null;
    }


    return devicesCache.find(
        device => {

            const databaseId =
                device.id !== null &&
                device.id !== undefined
                    ? String(
                        device.id
                    ).trim()
                    : "";


            const externalDeviceId =
                device.deviceId !== null &&
                device.deviceId !== undefined
                    ? String(
                        device.deviceId
                    ).trim()
                    : "";


            return possibleIdentifiers.some(
                identifier =>

                    identifier ===
                        databaseId ||

                    identifier ===
                        externalDeviceId
            );

        }
    ) || null;
}


/* ============================================================
   EVENT EDIT
   ============================================================ */

async function openEventEditForm(
    eventId
) {

    if (
        !getJwt()
    ) {

        showNotification(
            "Please login before editing a security event.",
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


    try {

        /*
         * Make sure the device cache is available before
         * populating the device dropdown.
         */

        if (
            devicesCache.length === 0
        ) {

            await loadDevices(false);
        }


        if (
            devicesCache.length === 0
        ) {

            throw new Error(
                "No devices are available. The event cannot be edited without its device."
            );
        }


        /*
         * Populate the dropdown BEFORE setting its value.
         */

        populateDeviceDropdown();


        /*
         * Resolve the event's device against both:
         *
         * - database ID
         * - external deviceId
         * - nested device.id
         * - nested device.deviceId
         */

        const selectedDevice =
            findDeviceForEvent(
                event
            );


        eventFormTitle.textContent =
            "Edit Security Event";


        saveEventButton.textContent =
            "Update Event";


        eventIdInput.value =
            identifier;


        /*
         * IMPORTANT:
         *
         * The select option value is the database ID.
         * Therefore use selectedDevice.id here rather than
         * blindly assigning event.deviceId.
         */

        eventDeviceInput.value =
            selectedDevice
                ? String(
                    selectedDevice.id
                )
                : "";


        eventTypeInput.value =
            event.eventType ?? "";


        eventSeverityInput.value =
            event.severity ?? "";


        eventSourceIpInput.value =
            event.sourceIp ?? "";


        eventDescriptionInput.value =
            event.description ?? "";


        const eventStatus =
            String(
                event.status ??
                "OPEN"
            ).toUpperCase();


        /*
         * Only select a status that actually exists in
         * the dropdown. Otherwise fall back to OPEN.
         */

        eventStatusInput.value =
            EVENT_STATUSES.includes(
                eventStatus
            )
                ? eventStatus
                : "OPEN";


        if (
            !selectedDevice
        ) {

            showNotification(
                "The event's device could not be matched to a registered device.",
                "warning"
            );
        }


        eventFormContainer.classList.remove(
            "hidden"
        );


        eventFormContainer.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });


    } catch (error) {

        showNotification(
            `Could not open the event for editing: ${error.message}`,
            "error"
        );
    }
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


            /*
             * The option value is ALWAYS the database ID.
             *
             * This is the ID expected by EventRequest.deviceId.
             */

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


function isValidEventStatus(
    status
) {

    return EVENT_STATUSES.includes(
        status
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


    /*
     * IMPORTANT FIX:
     *
     * Always read the selected status.
     *
     * Previously the status was only included during
     * updates. Therefore a newly-created event could
     * have its selected status ignored by the backend
     * and default to OPEN.
     */

    const status =
        String(
            eventStatusInput.value ||
            "OPEN"
        ).toUpperCase();


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


    /*
     * Validate status for BOTH create and update.
     */

    if (
        !isValidEventStatus(
            status
        )
    ) {

        showNotification(
            `Invalid event status: ${status}`,
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


    const eventId =
        eventIdInput.value.trim();


    const isUpdate =
        Boolean(eventId);


    /*
     * IMPORTANT FIX:
     *
     * status is now included for BOTH POST and PUT.
     *
     * This means selecting INVESTIGATING, RESOLVED or
     * CLOSED while creating a new event will actually be
     * sent to the Event Service.
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
            sourceIp,

        status:
            status

    };


    try {

        saveEventButton.disabled =
            true;


        showNotification(
            isUpdate
                ? "Updating security event..."
                : "Creating security event...",
            "info"
        );


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


        await loadSecurityEvents(false);


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


    const confirmed =
        confirm(
            `Delete security event "${event.eventId}"?\n\nThis action cannot be undone.`
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


        await loadSecurityEvents(false);


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

        await loadSecurityEvents(true);

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
                ).toUpperCase();


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
                ).toUpperCase();


            const statusClass =
                getEventStatusClass(
                    status
                );


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
   BUTTON EVENTS
   ============================================================ */

registerUserButton.addEventListener(
    "click",
    registerUser
);


clearRegistrationButton.addEventListener(
    "click",
    clearRegistrationForm
);


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


registerUsernameInput.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            registerUser();
        }
    }
);


registerPasswordInput.addEventListener(
    "keydown",
    event => {

        if (
            event.key === "Enter"
        ) {

            registerUser();
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
         * Restore username/role information associated
         * with the existing JWT.
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
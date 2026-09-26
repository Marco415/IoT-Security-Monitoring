const API_BASE = "/api/soc/dashboard";


document.addEventListener(
    "DOMContentLoaded",
    () => {

        document
            .getElementById("refreshButton")
            .addEventListener(
                "click",
                loadDashboard
            );

        loadDashboard();

    }
);


async function loadDashboard() {

    setConnectionStatus(
        "CONNECTING",
        "status-unknown"
    );

    try {

        const response =
            await fetch(API_BASE, {
                method: "GET",

                headers: {
                    "Accept": "application/json"
                }
            });


        if (response.status === 401) {

            setConnectionStatus(
                "UNAUTHORIZED",
                "status-down"
            );

            showAuthenticationMessage();

            return;
        }


        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`
            );
        }


        const dashboard =
            await response.json();


        renderDashboard(dashboard);


        setConnectionStatus(
            "CONNECTED",
            "status-up"
        );


    } catch (error) {

        console.error(
            "Dashboard error:",
            error
        );


        setConnectionStatus(
            "OFFLINE",
            "status-down"
        );

        document
            .getElementById("alertsContainer")
            .innerHTML = `
                <div class="loading">
                    Unable to load SOC dashboard.
                </div>
            `;
    }
}


function renderDashboard(data) {

    document
        .getElementById("totalEvents")
        .textContent =
        data.totalEvents ?? 0;


    document
        .getElementById("openAlerts")
        .textContent =
        data.openAlerts ?? 0;


    document
        .getElementById("highAlerts")
        .textContent =
        data.highAlerts ?? 0;


    document
        .getElementById("mediumAlerts")
        .textContent =
        data.mediumAlerts ?? 0;


    renderServices(
        data.services ?? []
    );


    renderAlerts(
        data.recentAlerts ?? []
    );


    document
        .getElementById("lastUpdated")
        .textContent =
        data.generatedAt
            ? new Date(
                data.generatedAt
            ).toLocaleString()
            : "-";
}


function renderServices(services) {

    const container =
        document.getElementById(
            "servicesContainer"
        );


    if (!services.length) {

        container.innerHTML = `
            <div class="loading">
                No service information available.
            </div>
        `;

        return;
    }


    let upCount = 0;


    container.innerHTML =
        services.map(service => {

            const isUp =
                service.status === "UP";


            if (isUp) {
                upCount++;
            }


            return `
                <div class="service-card">

                    <span class="service-name">
                        ${escapeHtml(
                            service.name
                        )}
                    </span>

                    <span class="
                        service-status
                        ${
                            isUp
                                ? "status-up"
                                : "status-down"
                        }
                    ">
                        ${isUp ? "● UP" : "● DOWN"}
                    </span>

                </div>
            `;

        }).join("");


    document
        .getElementById("serviceSummary")
        .textContent =
        `${upCount}/${services.length} services UP`;
}


function renderAlerts(alerts) {

    const container =
        document.getElementById(
            "alertsContainer"
        );


    if (!alerts.length) {

        container.innerHTML = `
            <div class="loading">
                No recent alerts.
            </div>
        `;

        return;
    }


    container.innerHTML =
        alerts.map(alert => {

            const severity =
                String(
                    alert.severity ?? "UNKNOWN"
                ).toLowerCase();


            return `
                <div class="alert-card">

                    <div class="
                        alert-severity
                        severity-${severity}
                    ">
                        ${escapeHtml(
                            alert.severity
                        )}
                    </div>

                    <div class="alert-rule">
                        ${escapeHtml(
                            alert.rule
                        )}
                    </div>

                    <div class="alert-service">
                        ${escapeHtml(
                            alert.serviceName ?? "-"
                        )}
                    </div>

                    <div class="alert-user">
                        ${escapeHtml(
                            alert.userId ?? "-"
                        )}
                    </div>

                    <div class="alert-status">
                        ${escapeHtml(
                            alert.status
                        )}
                    </div>

                </div>
            `;

        }).join("");
}


function setConnectionStatus(
    text,
    cssClass
) {

    const element =
        document.getElementById(
            "connectionStatus"
        );


    element.textContent = text;

    element.className =
        `status-badge ${cssClass}`;
}


function showAuthenticationMessage() {

    document
        .getElementById(
            "alertsContainer"
        )
        .innerHTML = `
            <div class="loading">
                Authentication required.
                Please log in through the main
                application first.
            </div>
        `;
}


function escapeHtml(value) {

    if (value === null ||
        value === undefined) {

        return "";
    }


    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
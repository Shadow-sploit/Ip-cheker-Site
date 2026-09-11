// ---------- Тема (тёмная/светлая) ----------
const root = document.documentElement;
const themeToggle = document.getElementById("theme-toggle");

function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    localStorage.setItem("ipwhois_theme", theme);
}

(function initTheme() {
    const saved = localStorage.getItem("ipwhois_theme");
    if (saved) {
        applyTheme(saved);
    } else {
        const prefersLight = window.matchMedia("(prefers-color-scheme: light)").matches;
        applyTheme(prefersLight ? "light" : "dark");
    }
})();

themeToggle.addEventListener("click", () => {
    const current = root.getAttribute("data-theme");
    applyTheme(current === "dark" ? "light" : "dark");
});

// ---------- Год в футере ----------
document.getElementById("year").textContent = new Date().getFullYear();

// ---------- Логика поиска WHOIS ----------
const form = document.getElementById("lookup-form");
const ipInput = document.getElementById("ip-input");
const useMyIpBtn = document.getElementById("use-my-ip");
const loader = document.getElementById("loader");
const resultsBox = document.getElementById("results");
const errorBox = document.getElementById("error-box");

function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}

function clearError() {
    errorBox.classList.add("hidden");
    errorBox.textContent = "";
}

function row(key, value) {
    return `<div class="k">${key}</div><div class="v">${value ?? "—"}</div>`;
}

function renderResults(data) {
    document.getElementById("general-info").innerHTML =
        row("IP-адрес", data.ip) +
        row("Дата запроса (UTC)", data.queried_at) +
        row("Регистратор (RIR)", data.asn_registry);

    document.getElementById("asn-info").innerHTML =
        row("ASN", data.asn) +
        row("Организация", data.asn_description) +
        row("Страна", data.asn_country_code) +
        row("Дата регистрации ASN", data.asn_date) +
        row("Диапазон ASN", data.asn_cidr);

    const net = data.network || {};
    document.getElementById("network-info").innerHTML =
        row("Название сети", net.name) +
        row("CIDR", net.cidr) +
        row("Начало диапазона", net.start_address) +
        row("Конец диапазона", net.end_address) +
        row("Страна", net.country) +
        row("Тип", net.type);

    const contactsEl = document.getElementById("contacts-info");
    if (data.contacts && data.contacts.length > 0) {
        contactsEl.innerHTML = data.contacts
            .map(
                (c) =>
                    row(
                        c.role ? c.role.join(", ") : "Контакт",
                        `${c.name || "—"} ${c.email && c.email.length ? "(" + c.email.join(", ") + ")" : ""}`
                    )
            )
            .join("");
    } else {
        contactsEl.innerHTML = `<p class="empty-hint">Контактные данные не опубликованы регистратором.</p>`;
    }

    resultsBox.classList.remove("hidden");
}

async function lookupIp(ip) {
    clearError();
    resultsBox.classList.add("hidden");
    loader.classList.remove("hidden");

    try {
        const res = await fetch(`/api/whois?ip=${encodeURIComponent(ip)}`);
        const data = await res.json();

        if (!res.ok) {
            showError(data.error || "Не удалось получить данные");
            return;
        }
        renderResults(data);
    } catch (err) {
        showError("Ошибка сети: не удалось связаться с сервером");
    } finally {
        loader.classList.add("hidden");
    }
}

form.addEventListener("submit", (e) => {
    e.preventDefault();
    const ip = ipInput.value.trim();
    if (!ip) return;
    lookupIp(ip);
});

useMyIpBtn.addEventListener("click", async () => {
    try {
        const res = await fetch("/api/myip");
        const data = await res.json();
        ipInput.value = data.ip;
        lookupIp(data.ip);
    } catch {
        showError("Не удалось определить ваш IP");
    }
});



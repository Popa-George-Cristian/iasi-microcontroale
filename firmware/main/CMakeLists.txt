idf_component_register(
    SRCS "main.c" "wifi_manager.c" "ids_engine.c" "firewall.c" "web_server.c"
    INCLUDE_DIRS "."
    EMBED_FILES "frontend/index.html" "frontend/style.css" "frontend/app.js"
)

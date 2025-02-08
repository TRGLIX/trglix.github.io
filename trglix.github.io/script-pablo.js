function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');

    if (sidebar.classList.contains('closed')) {
        sidebar.classList.remove('closed');
        mainContent.classList.remove('full-width');
    } else {
        sidebar.classList.add('closed');
        mainContent.classList.add('full-width');
    }
}

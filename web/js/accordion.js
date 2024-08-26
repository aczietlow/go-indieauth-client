document.addEventListener('DOMContentLoaded', function() {
    const headers = document.querySelectorAll('.accordion-header');

    headers.forEach(header => {
        header.addEventListener('click', function() {
            const content = this.nextElementSibling;
            if (content.classList.contains('expanded')) {
                content.classList.remove('expanded')
            } else {
                // If we only want a single item open at a time.
                // document.querySelectorAll('.expanded').forEach(item => {
                //     item.classList.remove('expanded')
                // });
                content.classList.add('expanded')
            }
        });
    });


});

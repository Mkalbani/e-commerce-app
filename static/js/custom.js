$(document).ready(function() {
    // Add to Cart button click event
    $('.btn-add-to-cart').on('click', function() {
        var product_id = $(this).data('product-id');

        // Send an AJAX POST request to the Flask route
        $.ajax({
            type: 'POST',
            url: '/add_to_cart/' + product_id,
            success: function(response) {
                // Handle the response if needed (e.g., display a success message)
            },
            error: function(err) {
                // Handle errors if the request fails
            }
        });
    });
});

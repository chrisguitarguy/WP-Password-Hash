WP Password Hash
================

Use PHP 5.5's new `password_*` API or fall back on Anthony Ferrara's
`password_compat` library.

Should be backwords compatible. Users will get new password hashes when the log
in.

### Requirements

PHP 5.3.7+. The plugin does a check for this. if the version requirement isn't
met none of the functions will be replaced.

### Changing the Cost Factor

Hook into `wp_password_hash_cost`. If the cost is different from the previous
cost, it should trigger a rehash of the password when the user next logs in.

    add_filter('wp_password_hash_cost', function () {
        return 16;
    });

<?php
/**
 * WP Password Hash
 *
 * @category    WordPress
 * @author      Christopher Davis <http://christopherdavis.me>
 * @copyright   2013 Christopher Davis
 * @license     http://opensource.org/licenses/MIT MIT
 */

function _wpph_get_cost()
{
    return apply_filters('wp_password_hash_cost', 12);
}

if (!function_exists('wp_hash_password')) {
    /**
     * See wp-includes/pluggable.php for docs on this function.
     */
    function wp_hash_password($password)
    {
        return password_hash($password, PASSWORD_BCRYPT, array(
            'cost'  => _wpph_get_cost(),
        ));
    }
}

if (!function_exists('wp_check_password')) {
    /**
     * See wp-includes/pluggable.php for docs on this function.
     */
    function wp_check_password($raw_password, $hash, $user_id='')
    {
        global $wp_hasher;

        // check for old style md5 passwords
        // note this differs from the core, which lets you see the new
        // updated hash in the `check_password` filter
        if (strlen($hash) <= 32) {
            $check = ($hash === md5($raw_password));
            if ($check && $user_id) {
                wp_set_password($raw_password, $user_id);
            }

            return apply_filters('check_password', $check, $raw_password, $hash, $user_id);
        }

        // Now we need to see if we have a case where the password needs a
        // rehash (eg. not bcrypt). If it does, we can set up $wp_hasher
        // and check the password. If we're good, reset the password with
        // our new `password_hash` goodness. A downside here is that this
        // will also catch passwords for re-hashing when the cost changes.
        // PHPass is able to handle bcrypt'd passwords, but that isn't exactly
        // ideal. For now, it stays until someone comes up with a better solution.
        $rehash = password_needs_rehash($hash, PASSWORD_BCRYPT, array(
            'cost'  => _wpph_get_cost(),
        ));

        if ($rehash) {
            if (empty($wp_hasher)) {
                require_once ABSPATH . 'wp-includes/class-phpass.php';
                $wp_hasher = new PasswordHash(8, true);
            }

            $check = $wp_hasher->CheckPassword($raw_password, $hash);

            if ($check && $user_id) {
                wp_set_password($raw_password, $user_id);
            }

            return apply_filters('check_password', $check, $raw_password, $hash, $user_id);
        }

        // finally, we can actually just use password_verify
        return apply_filters('check_password',
            password_verify($raw_password, $hash),
            $raw_password,
            $hash,
            $user_id
        );
    }
}

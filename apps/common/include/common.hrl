-include_lib("kernel/include/logger.hrl").

-define(INFO, "ss-subkey").
-define(NONCE_SIZE, 12).
-define(TAG_SIZE, 16).
-define(MAX_SIZE, 16#3fff).
-define(HEADER, ?MAX_SIZE + 1).
-define(ZERO_NONCE, <<0:?NONCE_SIZE/unit:8>>).
-define(RELAY_TIMOUT, timer:seconds(30)).
-define(DIAL_TIMEOUT, timer:seconds(5)).
-define(SOCK_OPTS,
        [{inet_backend, socket}, binary, {packet, 0}, {nodelay, true}, {active, false}]).

-type cipher_aead() :: aes_128_gcm | aes_256_gcm | chacha20_poly1305.
-type context() :: init() | encrypt_ctx() | decrypt_ctx().
-type init() :: {init, cipher_aead(), binary()}.
-type encrypt_ctx() :: {context, seal(), binary()}.
-type decrypt_ctx() :: {context, open(), binary(), non_neg_integer(), binary()}.
-type seal() :: fun((binary(), binary()) -> {binary(), binary(), binary()}).
-type open() :: fun((binary(), binary(), binary()) -> {binary(), binary()}).

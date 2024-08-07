-module(cipher).

-export([init/2, encrypt/2, decrypt/2]).

-include_lib("kernel/include/logger.hrl").

-record(init, {cipher, master_key, key_size}).
-record(chunk, {cipher, sub_key, nonce}).
-record(payload, {cipher, sub_key, nonce, length}).

-type ciphers() :: aes_128_gcm | aes_256_gcm | chacha20_poly1305.
-type state() :: #init{} | #chunk{} | #payload{}.

-export_type([state/0, ciphers/0]).

-define(INFO, "ss-subkey").
% key size = salt size, in bytes.
-define(KEY_SIZE,
        #{chacha20_poly1305 => 32,
          aes_256_gcm => 32,
          aes_128_gcm => 16}).
-define(NONCE_SIZE, 12).
-define(TAG_SIZE, 16).
-define(LENGTH_SIZE, 2).
-define(MAX_SIZE, 16#3fff).
-define(ZERO, <<0:?NONCE_SIZE/unit:8>>).

-spec init(Cipher, Pass) -> State
    when Cipher :: ciphers(),
         Pass :: string(),
         State :: state().
init(Cipher, Pass) ->
    case ?KEY_SIZE of
        #{Cipher := Len} ->
            {init, Cipher, derive_key(Pass, Len), Len};
        #{} ->
            ?LOG_ERROR("cipher: ~p is not supported", [Cipher]),
            exit(normal)
    end.

-spec encrypt(State, Input) -> {Output, State}
    when State :: state(),
         Input :: binary(),
         Output :: iolist().
encrypt(State, Input) ->
    encrypt(State, Input, []).

encrypt(State, <<>>, Acc) ->
    {lists:reverse(Acc), State};
encrypt({init, Cipher, MasterKey, KeySize}, Input, []) ->
    Salt = crypto:strong_rand_bytes(KeySize),     % key size = salt size
    SubKey = hkdf_sha1(MasterKey, Salt, KeySize),
    encrypt({chunk, Cipher, SubKey, ?ZERO}, Input, [Salt]);
encrypt({chunk, Cipher, SubKey, Nonce}, Input, Acc) ->
    Size = byte_size(Input) band ?MAX_SIZE,      % max size 0x3FFF
    {Cur, Rest} = split_binary(Input, Size),
    SizeBin = <<Size:?LENGTH_SIZE/unit:8>>,
    {Length, LengthTag} =
        crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, SizeBin, <<>>, true),
    {Payload, PayloadTag} =
        crypto:crypto_one_time_aead(Cipher, SubKey, inc(Nonce), Cur, <<>>, true),
    Bcc = [PayloadTag, Payload, LengthTag, Length] ++ Acc,      %concat from backward
    encrypt({chunk, Cipher, SubKey, iinc(Nonce)}, Rest, Bcc).

-spec decrypt(State, Input) -> Result
    when State :: state(),
         Input :: binary(),
         Output :: iolist(),
         Rest :: binary(),
         Result :: {Output, Rest, State} | error.
decrypt(State, Input) ->
    decrypt(State, Input, []).

% extract salt
decrypt({init, Cipher, MasterKey, KeySize}, Input, []) when byte_size(Input) >= KeySize ->
    {Salt, Rest} = split_binary(Input, KeySize),
    SubKey = hkdf_sha1(MasterKey, Salt, KeySize),
    decrypt({chunk, Cipher, SubKey, ?ZERO}, Rest, []);
% decrypt length
decrypt({chunk, Cipher, SubKey, Nonce},
        <<Data:?LENGTH_SIZE/binary, Tag:?TAG_SIZE/binary, Rest/binary>>,
        Acc) ->
    case crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, Data, <<>>, Tag, false) of
        error ->
            error;
        <<Length:?LENGTH_SIZE/unit:8>> ->
            decrypt({payload, Cipher, SubKey, inc(Nonce), Length}, Rest, Acc)
    end;
decrypt({payload, Cipher, SubKey, Nonce, Length}, Input, Acc)
    when byte_size(Input) >= Length + ?TAG_SIZE ->
    <<Data:Length/binary, Tag:?TAG_SIZE/binary, Rest/binary>> = Input,
    case crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, Data, <<>>, Tag, false) of
        error ->
            error;
        Payload ->
            decrypt({chunk, Cipher, SubKey, inc(Nonce)}, Rest, [Payload | Acc])
    end;
decrypt(State, Input, Acc) ->
    {lists:reverse(Acc), Input, State}.

-spec derive_key(Pass, Len) -> Key
    when Pass :: string(),
         Len :: non_neg_integer(),
         Key :: binary().
derive_key(Pass, Len) ->
    derive_key(list_to_binary(Pass), <<>>, Len).

derive_key(Pass, Pre, Len) when Len > 16 ->
    Cur = crypto:hash(md5, [Pre, Pass]),
    Rest = derive_key(Pass, Cur, Len - 16),
    <<Cur/binary, Rest/binary>>;
derive_key(Pass, Pre, _) ->
    crypto:hash(md5, [Pre, Pass]).

-spec hkdf_sha1(Key, Salt, Len) -> SubKey
    when Key :: binary(),
         Salt :: binary(),
         Len :: non_neg_integer(),
         SubKey :: binary().
hkdf_sha1(Key, Salt, Len) ->
    expand(crypto:mac(hmac, sha, Salt, Key), <<>>, 1, Len).

expand(Prk, Pre, I, Len) when Len > 16 ->
    Cur = crypto:mac(hmac, sha, Prk, <<Pre/binary, ?INFO, I>>),
    Rest = expand(Prk, Cur, I + 1, Len - 20),
    <<Cur/binary, Rest/binary>>;
expand(Prk, Pre, I, _) ->
    crypto:mac(hmac, sha, Prk, <<Pre/binary, ?INFO, I>>).

inc(I) ->
    add(I, 1).

iinc(I) ->
    add(I, 2).

add(<<I:12/little-unit:8>>, J) ->
    <<(I + J):12/little-unit:8>>.

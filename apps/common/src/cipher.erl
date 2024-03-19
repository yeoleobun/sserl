-module(cipher).

-export([encrypt/2]).
-export([init/2]).
-export([derive_key/2]).
-export([decrypt/2]).
-export([inc/1]).
-export([add/2]).

-record(state0,
        {cipher :: cipher(), master_key :: binary(), key_size :: non_neg_integer()}).
-record(state1, {cipher :: cipher(), sub_key :: binary(), nonce :: binary()}).
-record(satte2,
        {cipher :: cipher(),
         sub_key :: binary(),
         nonce :: binary(),
         length :: non_neg_integer()}).

-type cipher() :: aes_128_gcm | aes_256_gcm | chacha20_poly1305.

-define(INFO, "ss-subkey").
-define(KEY_SIZE, #{chacha20_poly1305 => 32}). % key size = salt size
-define(NONCE_SIZE, 12). % iv
-define(TAG_SIZE, 16).
-define(LENGTH_SIZE, 2).
-define(MAX_SIZE, 16#3fff).
-define(ZERO, <<0:?NONCE_SIZE/unit:8>>).

-spec init(Cipher, Pass) -> State
    when Cipher :: cipher(),
         Pass :: string(),
         State :: #state0{} | boolean().
init(Cipher, Pass) ->
    case ?KEY_SIZE of
        #{Cipher := Len} ->
            Key = derive_key(Pass, Len),
            {state0, Cipher, Key, Len};
        #{} ->
            exit("cipher not supported")
    end.

-spec encrypt(State, Input) -> {Output, State}
    when State :: #state0{} | #state1{},
         Input :: binary(),
         Output :: iolist().
encrypt(State, Input) ->
    encrypt(State, Input, []).

-spec encrypt(State, Input, Acc) -> {Output, State}
    when State :: #state0{} | #state1{},
         Input :: binary(),
         Acc :: iolist(),
         Output :: iolist().
encrypt(State, <<>>, Acc) ->
    {lists:reverse(Acc), State};
encrypt({state0, Cipher, MasterKey, KeySize}, Input, []) ->
    Salt = crypto:strong_rand_bytes(KeySize), % key size = salt size
    SubKey = hkdf_sha1(MasterKey, Salt, KeySize),
    encrypt({state1, Cipher, SubKey, ?ZERO}, Input, [Salt]);
encrypt({state1, Cipher, SubKey, Nonce} = State, Input, Acc) ->
    Size = byte_size(Input) band ?MAX_SIZE,
    {Cur, Rest} = split_binary(Input, Size),
    SizeBin = <<Size:?LENGTH_SIZE/unit:8>>,
    {Length, LengthTag} =
        crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, SizeBin, <<>>, true),
    {Payload, PayloadTag} =
        crypto:crypto_one_time_aead(Cipher, SubKey, inc(Nonce), Cur, <<>>, true),
    Bcc = [PayloadTag, Payload, LengthTag, Length] ++ Acc, %concat from backward
    encrypt(State#state1{nonce = iinc(Nonce)}, Rest, Bcc).

-spec decrypt(State, Input) -> {Output, Rest, State}
    when State :: #state0{} | #state1{} | #satte2{},
         Input :: binary(),
         Output :: iolist(),
         Rest :: binary().
decrypt(State, Input) ->
    decrypt(State, Input, []).

decrypt({state0, Cipher, MasterKey, KeySize}, Input, [])
    when byte_size(Input) >= KeySize ->
    {Salt, Rest} = split_binary(Input, KeySize),
    SubKey = hkdf_sha1(MasterKey, Salt, KeySize),
    decrypt({state1, Cipher, SubKey, ?ZERO}, Rest, []);
decrypt({state1, Cipher, SubKey, Nonce}, Input, Output)
    when byte_size(Input) >= ?LENGTH_SIZE + ?TAG_SIZE ->
    <<Data:?LENGTH_SIZE/binary, Tag:?TAG_SIZE/binary, Rest/binary>> = Input,
    <<Length:?LENGTH_SIZE/unit:8>> =
        crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, Data, <<>>, Tag, false),
    decrypt({state2, Cipher, SubKey, inc(Nonce), Length}, Rest, Output);
decrypt({state2, Cipher, SubKey, Nonce, Length}, Input, Output)
    when byte_size(Input) >= Length + ?TAG_SIZE ->
    <<Data:Length/binary, Tag:?TAG_SIZE/binary, Rest/binary>> = Input,
    Payload = crypto:crypto_one_time_aead(Cipher, SubKey, Nonce, Data, <<>>, Tag, false),
    decrypt({state1, Cipher, SubKey, inc(Nonce)}, Rest, [Payload | Output]);
decrypt(State, Input, Output) ->
    {lists:reverse(Output), Input, State}.

-spec derive_key(Pass, Len) -> Key
    when Pass :: [char()],
         Len :: integer(),
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
         Len :: integer(),
         SubKey :: binary().
hkdf_sha1(Key, Salt, Len) ->
    Prk = crypto:mac(hmac, sha, Salt, Key), % extract
    expand(Prk, <<>>, 1, Len).

expand(Prk, Pre, I, Len) when Len > 16 ->
    Cur = crypto:mac(hmac, sha, Prk, <<Pre/binary, ?INFO, I>>),
    Rest = expand(Prk, Cur, I + 1, Len - 20),
    <<Cur/binary, Rest/binary>>;
expand(Prk, Pre, I, _) ->
    crypto:mac(hmac, sha, Prk, <<Pre/binary, ?INFO, I>>).

-spec inc(binary()) -> binary().
inc(I) ->
    add(I, 1).

-spec iinc(binary()) -> binary().
iinc(I) ->
    add(I, 2).

-spec add(binary(), non_neg_integer()) -> binary().
add(<<I:12/little-unit:8>>, J) ->
    <<(I + J):12/little-unit:8>>.

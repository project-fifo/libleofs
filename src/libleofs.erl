-module(libleofs).

%% Cluster Operations
-export([detach/3, suspend/3, resume/3, start/2, rebalance/2, whereis/3,
         recover_file/3, recover_node/3, recover_ring/3, recover_cluster/3,
         rollback/3]).

%% MQ Operations on storage nodes
-export([mq_stats/3, mq_suspend/4, mq_resume/4]).

%% [Storage Maintenance]
-export([du/3, compact_start/4, compact_start/5,
         compact_suspend/3, compact_resume/3, compact_status/3]).

%% [Gateway Maintenance]
-export([purge/3, remove/3]).

%% [S3-related Maintenance]
-export([create_user/3, create_user/4, delete_user/3, update_user_role/4,
         update_user_password/4, get_users/2, add_endpoint/3, delete_endpoint/3,
         get_endpoints/2, add_bucket/4, delete_bucket/4, chown_bucket/4,
         update_acl/4, get_buckets/2, get_buckets/3]).

%% [Multi-DC Replication]
-export([join_cluster/4, remove_cluster/4, cluster_status/2]).

%% [Misc]
-export([login/4, version/2, status/2, status/3]).

%% [Cluster Operation]
-define(START, "start").
-define(DETACH, "detach").
-define(SUSPEND, "suspend").
-define(RESUME, "resume").
-define(REBALANCE, "rebalance").
-define(WHEREIS, "whereis").
-define(RECOVER_FILE, "recover file").
-define(RECOVER_NODE, "recover node").
-define(RECOVER_RING, "recover ring").
-define(RECOVER_CLUSTER, "recover ring").
-define(ROLLBACK, "rollback").

%% [MQ Operations on storage nodes]
-define(MQ_STATS, "mq-stats").
-define(MQ_SUSPEND, "mq-suspend").
-define(MQ_RESUME, "mq-resume").

%% [Storage Maintenance]
-define(DU, "du").
-define(COMPACT_START, "compact start").
-define(COMPACT_SUSPEND, "compact suspend").
-define(COMPACT_RESUME, "compact resume").
-define(COMPACT_STATUS, "compact status").

%% [Gateway Maintenance]
-define(PURGE, "purge").
-define(REMOVE, "remove").

%% [S3-related Maintenance]
-define(CRE_USER, "create-user").
-define(DEL_USER, "delete-user").
-define(UPD_USER_ROLE, "update-user-role").
-define(UPD_USER_PASS, "update-user-password").
-define(GET_USERS, "get-users").

-define(ADD_ENDPOINT, "add-endpoint").
-define(DEL_ENDPOINT, "delete-endpoint").
-define(GET_ENDPOINTS, "get-endpoints").

-define(ADD_BUCKET, "add-bucket").
-define(DEL_BUCKET, "delete-bucket").
-define(GET_BUCKETS, "get-buckets").
-define(GET_BUCKET, "get-bucket").
-define(CHOWN_BUCKET, "chown-bucket").
-define(UPDATE_ACL, "update-acl").

%% [Multi-DC Replication]
-define(JOIN_CLUSTER, "join-cluster").
-define(REMOVE_CLUSTER, "remove-cluster").
-define(CLUSTER_STATUS, "cluster-status").

%% [Misc]
-define(VERSION, "version").
-define(STATUS, "status").
-define(DUMP_RING, "dump-ring").
-define(LOGIN, "login").

%% Constants
-define(DEF_TIMEOUT, 5000).

-type host() :: inet:hostname() | inet:ip_address().
-type net_port() :: inet:port_number().
-type str() :: iolist() | binary().
-type leo_reply() :: {ok, term()} | {error, term()}.


%% ===================================================================
%% Cluster Operation
%% ===================================================================

-spec start(Host::host(), Port::net_port()) ->
                   leo_reply().
start(Host, Port) ->
    cmd(Host, Port, ?START).

-spec detach(Host::host(), Port::net_port(), Node::str()) ->
                    leo_reply().

detach(Host, Port, Node) ->
    cmd(Host, Port, [?DETACH, $\s, Node]).

-spec suspend(Host::host(), Port::net_port(), Node::str()) ->
                     leo_reply().

suspend(Host, Port, Node) ->
    cmd(Host, Port, [?SUSPEND, $\s, Node]).

-spec resume(Host::host(), Port::net_port(), Node::str()) ->
                    leo_reply().

resume(Host, Port, Node) ->
    cmd(Host, Port, [?RESUME, $\s, Node]).

-spec rebalance(Host::host(), Port::net_port()) ->
                       leo_reply().

rebalance(Host, Port) ->
    cmd(Host, Port, ?REBALANCE).

-spec whereis(Host::host(), Port::net_port(), Path::str()) ->
                     leo_reply().

whereis(Host, Port, Path) ->
    case cmd(Host, Port, [?WHEREIS, $\s, Path]) of
        {ok, [{<<"assigned_info">>, Info}]} ->
            {ok, Info};
        O ->
            O
    end.

-spec recover_file(Host::host(), Port::net_port(), Path::str()) ->
                          leo_reply().

recover_file(Host, Port, Path) ->
    cmd(Host, Port, [?RECOVER_FILE, $\s, Path]).

-spec recover_node(Host::host(), Port::net_port(), Node::str()) ->
                          leo_reply().

recover_node(Host, Port, Node) ->
    cmd(Host, Port, [?RECOVER_NODE, $\s, Node]).

-spec recover_ring(Host::host(), Port::net_port(), Node::str()) ->
                          leo_reply().

recover_ring(Host, Port, Node) ->
    cmd(Host, Port, [?RECOVER_RING, $\s, Node]).

-spec recover_cluster(Host::host(), Port::net_port(), ClusterID::str()) ->
                             leo_reply().

recover_cluster(Host, Port, ClusterID) ->
    cmd(Host, Port, [?RECOVER_CLUSTER, $\s, ClusterID]).

-spec rollback(Host::host(), Port::net_port(), Node::str()) ->
                             leo_reply().

rollback(Host, Port, Node) ->
    cmd(Host, Port, [?ROLLBACK, $\s, Node]).

%% ===================================================================
%% MQ Operations on storage nodes
%% ===================================================================

-spec mq_stats(Host::host(), Port::net_port(), Node::str()) ->
                             leo_reply().

mq_stats(Host, Port, Node) ->
    cmd(Host, Port, [?MQ_STATS, $\s, Node]).

-spec mq_suspend(Host::host(), Port::net_port(), Node::str(), MQID::str()) ->
                             leo_reply().

mq_suspend(Host, Port, Node, MQID) ->
    cmd(Host, Port, [?MQ_SUSPEND, $\s, Node, $\s, MQID]).

-spec mq_resume(Host::host(), Port::net_port(), Node::str(), MQID::str()) ->
                             leo_reply().

mq_resume(Host, Port, Node, MQID) ->
    cmd(Host, Port, [?MQ_RESUME, $\s, Node, $\s, MQID]).

%% ===================================================================
%% Storage Maintenance
%% ===================================================================

-spec du(Host::host(), Port::net_port(), Node::str()) ->
                leo_reply().

du(Host, Port, Node) ->
    cmd(Host, Port, [?DU, $\s, Node]).

-spec compact_start(Host::host(), Port::net_port(), Node::str(),
                    NumOfTargets::pos_integer(),
                    NumOfConcurrents::pos_integer()) ->
                           leo_reply().

compact_start(Host, Port, Node, NumOfTargets, NumOfConcurrents)
  when is_integer(NumOfTargets), NumOfTargets > 0,
       is_integer(NumOfConcurrents), NumOfConcurrents > 0 ->
    cmd(Host, Port, [?COMPACT_START, $\s, Node,
                     $\s, integer_to_list(NumOfTargets),
                     $\s, integer_to_list(NumOfConcurrents)]).

-spec compact_start(Host::host(), Port::net_port(), Node::str(),
                    NumOfTargets::pos_integer() | all) ->
                           leo_reply().

compact_start(Host, Port, Node, all) ->
    cmd(Host, Port, [?COMPACT_START, $\s, Node, " all"]);

compact_start(Host, Port, Node, NumOfTargets)
  when is_integer(NumOfTargets), NumOfTargets > 0 ->
    cmd(Host, Port, [?COMPACT_START, $\s, Node,
                     $\s, integer_to_list(NumOfTargets)]).

-spec compact_suspend(Host::host(), Port::net_port(), Node::str()) ->
                             leo_reply().

compact_suspend(Host, Port, Node) ->
    cmd(Host, Port, [?COMPACT_SUSPEND, $\s, Node]).

-spec compact_resume(Host::host(), Port::net_port(), Node::str()) ->
                            leo_reply().

compact_resume(Host, Port, Node) ->
    cmd(Host, Port, [?COMPACT_RESUME, $\s, Node]).

-spec compact_status(Host::host(), Port::net_port(), Node::str()) ->
                            leo_reply().

compact_status(Host, Port, Node) ->
    cmd(Host, Port, [?COMPACT_STATUS, $\s, Node]).

%% ===================================================================
%% Gateway Maintenance
%% ===================================================================

-spec purge(Host::host(), Port::net_port(), Path::str()) ->
                   leo_reply().

purge(Host, Port, Path) ->
    cmd(Host, Port, [?PURGE, $\s, Path]).

-spec remove(Host::host(), Port::net_port(), Node::str()) ->
                    leo_reply().

remove(Host, Port, Node) ->
    cmd(Host, Port, [?REMOVE, $\s, Node]).

%% ===================================================================
%% S3-related Maintenance
%% ===================================================================

-spec create_user(Host::host(), Port::net_port(), UserID::str()) ->
                         leo_reply().

create_user(Host, Port, UserID) ->
    cmd(Host, Port, [?CRE_USER, $\s, UserID]).

-spec create_user(Host::host(), Port::net_port(), UserID::str(),
                  Password::str()) ->
                         leo_reply().

create_user(Host, Port, UserID, Password) ->
    cmd(Host, Port, [?CRE_USER, $\s, UserID, $\s, Password]).

-spec delete_user(Host::host(), Port::net_port(), UserID::str()) ->
                         leo_reply().

delete_user(Host, Port, UserID) ->
    cmd(Host, Port, [?DEL_USER, $\s, UserID]).


-spec update_user_role(Host::host(), Port::net_port(), UserID::str(),
                       RoleID::str()) ->
                              leo_reply().

update_user_role(Host, Port, UserID, RoleID) ->
    cmd(Host, Port, [?UPD_USER_ROLE, $\s, UserID, $\s, RoleID]).

-spec update_user_password(Host::host(), Port::net_port(), UserID::str(),
                           Password::str()) ->
                                  leo_reply().

update_user_password(Host, Port, UserID, Password) ->
    cmd(Host, Port, [?UPD_USER_PASS, $\s, UserID, $\s, Password]).

-spec get_users(Host::host(), Port::net_port()) ->
                       leo_reply().

get_users(Host, Port) ->
    case cmd(Host, Port, ?GET_USERS) of
        {ok, [{<<"users">>, Us}]} ->
            {ok, Us};
        O ->
            O
    end.

-spec add_endpoint(Host::host(), Port::net_port(), Endpoint::str()) ->
                          leo_reply().

add_endpoint(Host, Port, Endpoint) ->
    cmd(Host, Port, [?ADD_ENDPOINT, $\s, Endpoint]).

-spec delete_endpoint(Host::host(), Port::net_port(), Endpoint::str()) ->
                             leo_reply().

delete_endpoint(Host, Port, Endpoint) ->
    cmd(Host, Port, [?DEL_ENDPOINT, $\s, Endpoint]).

-spec get_endpoints(Host::host(), Port::net_port()) ->
                           leo_reply().

get_endpoints(Host, Port) ->
    case cmd(Host, Port, ?GET_ENDPOINTS) of
        {ok, [{<<"endpoints">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

-spec add_bucket(Host::host(), Port::net_port(), Bucket::str(),
                 AccessKeyID::str()) ->
                        leo_reply().

add_bucket(Host, Port, Bucket, AccessKeyID) ->
    cmd(Host, Port, [?ADD_BUCKET, $\s, Bucket, $\s, AccessKeyID]).

-spec delete_bucket(Host::host(), Port::net_port(), Bucket::str(),
                    AccessKeyID::str()) ->
                           leo_reply().

delete_bucket(Host, Port, Bucket, AccessKeyID) ->
    cmd(Host, Port, [?DEL_BUCKET, $\s, Bucket, $\s, AccessKeyID]).

-spec get_buckets(Host::host(), Port::net_port()) ->
                         leo_reply().

get_buckets(Host, Port) ->
    case cmd(Host, Port, ?GET_BUCKETS) of
        {ok, [{<<"buckets">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

-spec get_buckets(Host::host(), Port::net_port(),
                  AccessKeyID::str()) ->
                         leo_reply().

get_buckets(Host, Port, AccessKeyID) ->
    case cmd(Host, Port, [?GET_BUCKET, $\s, AccessKeyID]) of
        {ok, [{<<"buckets">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

-spec chown_bucket(Host::host(), Port::net_port(), Bucket::str(),
                    AccessKeyID::str()) ->
                           leo_reply().

chown_bucket(Host, Port, Bucket, AccessKeyID) ->
    cmd(Host, Port, [?CHOWN_BUCKET, $\s, Bucket, $\s, AccessKeyID]).


-spec update_acl(Host::host(), Port::net_port(), Bucket::str(),
                 Permission:: public_read | public_read | public_read_write) ->
                           leo_reply().
update_acl(Host, Port, Bucket, private) ->
    cmd(Host, Port, [?UPDATE_ACL, $\s, Bucket, $\s, "private"]);
update_acl(Host, Port, Bucket, public_read) ->
    cmd(Host, Port, [?UPDATE_ACL, $\s, Bucket, $\s, "public-read"]);
update_acl(Host, Port, Bucket, public_read_write) ->
    cmd(Host, Port, [?UPDATE_ACL, $\s, Bucket, $\s, "public-read-write"]).

%% ===================================================================
%% Multi-DC Replication
%% ===================================================================

-spec join_cluster(Host::host(), Port::net_port(), BucketRemoteMaster::str(),
                   RemoteSlave::str()) ->
                          leo_reply().
join_cluster(Host, Port, RemoteMaster, RemoteSlave) ->
    cmd(Host, Port, [?JOIN_CLUSTER, $\s, RemoteMaster, $\s, RemoteSlave]).

-spec remove_cluster(Host::host(), Port::net_port(), BucketRemoteMaster::str(),
                   RemoteSlave::str()) ->
                          leo_reply().
remove_cluster(Host, Port, RemoteMaster, RemoteSlave) ->
    cmd(Host, Port, [?REMOVE_CLUSTER, $\s, RemoteMaster, $\s, RemoteSlave]).

-spec cluster_status(Host::host(), Port::net_port()) ->
                          leo_reply().
cluster_status(Host, Port) ->
    cmd(Host, Port, ?CLUSTER_STATUS).

%% ===================================================================
%% Misc
%% ===================================================================

-spec version(Host::host(), Port::net_port()) ->
                     {ok, Version::binary()} | {error, term()}.
version(Host, Port) ->
    case cmd(Host, Port, ?VERSION) of
        {ok, [{<<"result">>, Vsn}]} ->
            {ok, Vsn};
        O ->
            O
    end.

-spec login(Host::host(), Port::net_port(),
            User::str(), Pass::str()) ->
                   leo_reply().

login(Host, Port, User, Pass) ->
    case cmd(Host, Port, [?LOGIN, $\s, User, $\s, Pass]) of
        {ok, [{<<"buckets">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

-spec status(Host::host(), Port::net_port()) ->
                    leo_reply().

status(Host, Port) ->
    cmd(Host, Port, ?STATUS).

-spec status(Host::host(), Port::net_port(), Node::str()) ->
                    leo_reply().

status(Host, Port, Node) ->
    cmd(Host, Port, [?STATUS, $\s, Node]).


%% ===================================================================
%% Internal functions
%% ===================================================================

-spec cmd(Host::host(), Port::net_port(), Comand::str()) ->
                 leo_reply().

cmd(Host, Port, Cmd) ->
    lager:debug("[leo] < ~s", [Cmd]),
    Opts = [binary, {active, false}, {packet, line}],
    {ok, Sock} = gen_tcp:connect(Host, Port, Opts, ?DEF_TIMEOUT),
    ok = gen_tcp:send(Sock, [Cmd, $\n]),
    Res = do_recv_and_decode(Sock),
    gen_tcp:close(Sock),
    Res.

%% @private Receive all data sent from the peer and
%%          decode the complete json string.
do_recv_and_decode(Sock) ->
    do_recv_and_decode(Sock, <<>>).

do_recv_and_decode(Sock, Buf) ->
    case gen_tcp:recv(Sock, 0, ?DEF_TIMEOUT) of
        {ok, R} ->
            NewBuf = <<Buf/binary, R/binary>>,
            case catch decode(NewBuf) of
                {'EXIT', _Cause} ->
                    %% Since the body received is still incomplete,
                    %% try gen_tcp_recv again
                    do_recv_and_decode(Sock, NewBuf);
                Res ->
                    Res
            end;
        {error, E} ->
            {error, E}
    end.

-spec decode(Reply::binary()) ->
                    leo_reply().

decode(Reply) ->
    lager:debug("[leo] > ~p", [Reply]),
    case jsx:decode(Reply) of
        [{<<"error">>, E}] ->
            {error, E};
        O ->
            {ok, O}
    end.

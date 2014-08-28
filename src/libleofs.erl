-module(libleofs).

%% Cluster Operations
-export([detach/3, suspend/3, resume/3, start/2, rebalance/2, whereis/3,
         recover_file/3, recover_node/3, recover_ring/3, recover_cluster/3]).

%% [Storage Maintenance]
-export([du/3, compact_start/4, compact_start/5,
         compact_suspend/3, compact_resume/3, compact_status/3]).

%% [Gateway Maintenance]
-export([purge/3, remove/3]).

%% [S3-related Maintenance]
-export([create_user/3, create_user/4, delete_user/3, update_user_role/4,
         update_user_password/4, get_users/2, add_endpoint/3, delete_endpoint/3,
         get_endpoints/2, add_bucket/3, delete_bucket/3, chowl_bucket/4,
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

%% [Cluster Operation]
start(Host, Port) ->
    cmd(Host, Port, ?START).

detach(Host, Port, Node) ->
    cmd(Host, Port, [?DETACH, $\s, Node]).

suspend(Host, Port, Node) ->
    cmd(Host, Port, [?SUSPEND, $\s, Node]).

resume(Host, Port, Node) ->
    cmd(Host, Port, [?RESUME, $\s, Node]).

rebalance(Host, Port) ->
    cmd(Host, Port, ?REBALANCE).

whereis(Host, Port, Path) ->
    case cmd(Host, Port, [?WHEREIS, $\s, Path]) of
        {ok, [{<<"assigned_info">>, Info}]} ->
            {ok, Info};
        O ->
            O
    end.

recover_file(Host, Port, Path) ->
    cmd(Host, Port, [?RECOVER_FILE, $\s, Path]).

recover_node(Host, Port, Node) ->
    cmd(Host, Port, [?RECOVER_NODE, $\s, Node]).

recover_ring(Host, Port, Node) ->
    cmd(Host, Port, [?RECOVER_RING, $\s, Node]).

recover_cluster(Host, Port, ClusterID) ->
    cmd(Host, Port, [?RECOVER_CLUSTER, $\s, ClusterID]).

%% [Storage Maintenance]
du(Host, Port, Node) ->
    cmd(Host, Port, [?DU, $\s, Node]).

compact_start(Host, Port, Node, NumOfTargets, NumOfConcurrents)
  when is_integer(NumOfTargets),
       is_integer(NumOfConcurrents) ->
    cmd(Host, Port, [?COMPACT_START, $\s, Node,
                       $\s, integer_to_list(NumOfTargets),
                       $\s, integer_to_list(NumOfConcurrents)]).

compact_start(Host, Port, Node, all) ->
    cmd(Host, Port, [?COMPACT_START, $\s, Node, " all"]);

compact_start(Host, Port, Node, NumOfTargets) when is_integer(NumOfTargets) ->
    cmd(Host, Port, [?COMPACT_START, $\s, Node,
                       $\s, integer_to_list(NumOfTargets)]).

compact_suspend(Host, Port, Node) ->
    cmd(Host, Port, [?COMPACT_SUSPEND, $\s, Node]).

compact_resume(Host, Port, Node) ->
    cmd(Host, Port, [?COMPACT_RESUME, $\s, Node]).

compact_status(Host, Port, Node) ->
    cmd(Host, Port, [?COMPACT_STATUS, $\s, Node]).

%% [Gateway Maintenance]
purge(Host, Port, Path) ->
    cmd(Host, Port, [?PURGE, $\s, Path]).

remove(Host, Port, Node) ->
    cmd(Host, Port, [?REMOVE, $\s, Node]).


%% [S3-related Maintenance]
create_user(Host, Port, UserID) ->
    cmd(Host, Port, [?CRE_USER, $\s, UserID]).

create_user(Host, Port, UserID, Password) ->
    cmd(Host, Port, [?CRE_USER, $\s, UserID, $\s, Password]).

delete_user(Host, Port, UserID) ->
    cmd(Host, Port, [?DEL_USER, $\s, UserID]).

update_user_role(Host, Port, UserID, RoleID) ->
    cmd(Host, Port, [?UPD_USER_ROLE, $\s, UserID, $\s, RoleID]).

update_user_password(Host, Port, UserID, Password) ->
    cmd(Host, Port, [?UPD_USER_PASS, $\s, UserID, $\s, Password]).

get_users(Host, Port) ->
    case cmd(Host, Port, ?GET_USERS) of
        {ok, [{<<"users">>, Us}]} ->
            {ok, Us};
        O ->
            O
        end.

add_endpoint(Host, Port, Endpoint) ->
    cmd(Host, Port, [?ADD_ENDPOINT, $\s, Endpoint]).

delete_endpoint(Host, Port, Endpoint) ->
    cmd(Host, Port, [?DEL_ENDPOINT, $\s, Endpoint]).

get_endpoints(Host, Port) ->
    case cmd(Host, Port, ?GET_ENDPOINTS) of
        {ok, [{<<"endpoints">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

add_bucket(Host, Port, Bucket) ->
    cmd(Host, Port, [?ADD_BUCKET, $\s, Bucket]).

delete_bucket(Host, Port, Bucket) ->
    cmd(Host, Port, [?DEL_BUCKET, $\s, Bucket]).

get_buckets(Host, Port) ->
    case cmd(Host, Port, ?GET_BUCKETS) of
        {ok, [{<<"buckets">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

get_buckets(Host, Port, AccessKeyID) ->
    case cmd(Host, Port, [?GET_BUCKET, $\s, AccessKeyID]) of
        {ok, [{<<"buckets">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

chowl_bucket(Host, Port, Bucket, AccessKeyID) ->
    cmd(Host, Port, [?CHOWN_BUCKET, $\s, Bucket, $\s, AccessKeyID]).

update_acl(Host, Port, Bucket, private) ->
    cmd(Host, Port, [?UPDATE_ACL, $\s, Bucket, $\s, "private"]);
update_acl(Host, Port, Bucket, public_read) ->
    cmd(Host, Port, [?UPDATE_ACL, $\s, Bucket, $\s, "public-read"]);
update_acl(Host, Port, Bucket, public_read_write) ->
    cmd(Host, Port, [?UPDATE_ACL, $\s, Bucket, $\s, "public-read-write"]).

%% [Multi-DC Replication]

join_cluster(Host, Port, RemoteMaster, RemoteSlave) ->
    cmd(Host, Port, [?JOIN_CLUSTER, $\s, RemoteMaster, $\s, RemoteSlave]).

remove_cluster(Host, Port, RemoteMaster, RemoteSlave) ->
    cmd(Host, Port, [?REMOVE_CLUSTER, $\s, RemoteMaster, $\s, RemoteSlave]).

cluster_status(Host, Port) ->
    cmd(Host, Port, ?CLUSTER_STATUS).

%% [Misc]

version(Host, Port) ->
    case cmd(Host, Port, ?VERSION) of
        {ok, [{<<"result">>, Vsn}]} ->
            {ok, Vsn};
        O ->
            O
end.

login(Host, Port, User, Pass) ->
    case cmd(Host, Port, [?LOGIN, $\s, User, $\s, Pass]) of
        {ok, [{<<"buckets">>, Bs}]} ->
            {ok, Bs};
        O ->
            O
    end.

status(Host, Port) ->
    cmd(Host, Port, ?STATUS).

status(Host, Port, Node) ->
    cmd(Host, Port, [?STATUS, $\s, Node]).

cmd(Host, Port, Cmd) ->
    Opts = [binary, {active, false}, {packet, line}],
    {ok, Sock} = gen_tcp:connect(Host, Port, Opts),
    ok = gen_tcp:send(Sock, [Cmd, $\n]),
    Res = case gen_tcp:recv(Sock, 0) of
              {ok, R} ->
                  case jsx:decode(R) of
                      [{<<"error">>, E}] ->
                          {error, E};
                      O ->
                          {ok, O}
                  end;
              E ->
                  E
          end,
    gen_tcp:close(Sock),
    Res.

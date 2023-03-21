/*Define topology*/
#define NODES 5 /*Number of routers*/
#define NB_OF_INTERFACES 9 /*Number of interfaces*/

#define BUFFER_SIZE 4
#define INFINITE_METRIC 255 /*For the RPC in AssertCancel*/

/*Router information*/
#define MY_RPC(node_id) node_info[node_id].my_rpc
#define ROUTER_INTEREST(node_id) node_info[node_id].router_interest
#define ROUTER_INTEREST_UPSTREAM(node_id) node_info[node_id].router_interest_upstream 
#define NEIGHBORS_OF_INTERFACE(node_id, interface_id) node_info[node_id].neighbors_at_each_interface[interface_id]

/*Interface information*/
#define INTERFACE_TYPE(node_id, interface_id) node_info[node_id].node_interface[interface_id].interface_type
#define INTERFACE_POTENTIAL_AW(node_id, interface_id) node_info[node_id].node_interface[interface_id].potential_aw
#define INTERFACE_ASSERT_STATE(node_id, interface_id) node_info[node_id].node_interface[interface_id].my_assert_state
#define INTERFACE_INTEREST(node_id, interface_id) node_info[node_id].node_interface[interface_id].my_interest
#define DOWNSTREAM_INTEREST(node_id, interface_id) node_info[node_id].node_interface[interface_id].downstream_interest
#define UPSTREAM_INTEREST(node_id, interface_id) node_info[node_id].node_interface[interface_id].upstream_interest

/*Interface neighbor's information*/
#define INTERFACE_NEIGHBOR_RPC(node_id, interface_id, neighbor_id) node_info[node_id].node_interface[interface_id].neighbor_state[neighbor_id].rpc
#define NEIGHBOR_INTEREST(node_id, interface_id, neighbor_id) node_info[node_id].node_interface[interface_id].neighbor_state[neighbor_id].interest

/*Function to evaluate RPC*/
#define betterRpc(id1, rpc1, id2, rpc2) ((rpc1 < rpc2) || (rpc1 == rpc2 && id1 > id2))
/*Function to check if an interface is a neighbour of another interface*/
#define IS_NEIGHBOR(node_id, interface_id, neighbor_id) ((NEIGHBORS_OF_INTERFACE(node_id, interface_id) & (1 << neighbor_id)) != 0)

/*Defines the possible types of states and messages*/
mtype = {root, non_root, not_interface}; //interface can be of type Root or Non-Root
mtype = {assert_msg, join_msg, prune_msg}; //types of messages 
mtype = {aw, al, na}; //assert states
mtype = {di, ndi, ui, nui, in, ni} //interest states
mtype = {none};

/*Defines parameter of neighbors to store*/
typedef NEIGHBORS {
  
  byte rpc = INFINITE_METRIC;
  bool interest = false;
}

/*Defines parameter of interface to store*/
typedef INTERFACE_CONFIGURATION {

  mtype interface_type = not_interface;
  mtype potential_aw = none;
  mtype my_assert_state = na;
  bool my_interest = false;
  mtype downstream_interest = ndi;
  mtype upstream_interest = nui;
  NEIGHBORS neighbor_state[NB_OF_INTERFACES];
}

/*Defines parameter of router to store*/
typedef NODE_CONFIGURATION {
  byte my_rpc = 0;
  mtype router_interest = ni;
  bool router_interest_upstream = false
  short neighbors_at_each_interface[NB_OF_INTERFACES]=0;
  INTERFACE_CONFIGURATION node_interface[NB_OF_INTERFACES];
}

/*Initializes the Routers*/
NODE_CONFIGURATION node_info[NODES];

/*Defines communication channels;
  if msg type is join or prune RPC is 0*/
chan ch[NB_OF_INTERFACES] = [BUFFER_SIZE] of {mtype, byte, byte} //<msg_type, neighbor_id, rpc>;

/*Sends msg that needs to be multicasted to all neighbors (Assert msg)*/
inline sendMsg(node_id, msg_type, interface_id, rpc) {
	  byte i;
    atomic{
      for (i : 0 .. (NB_OF_INTERFACES-1)) {
        sendMsgUnicast(node_id, msg_type, interface_id, rpc, i);
      }
    }
}

/*Sends a unicasts msg*/
inline sendMsgUnicast(node_id, msg_type, interface_id, rpc, dst) {
	atomic{
    if
    :: IS_NEIGHBOR(node_id, interface_id, dst) ->
        ch[dst] ! msg_type(interface_id, rpc);
    :: else ->
        skip;
    fi;
  }
}

/*Resets interface*/
inline clearInterface(node_id, interface_id, last_type) {
  byte i;
  atomic{
    if
    :: INTERFACE_TYPE(node_id, interface_id) != not_interface ->
        INTERFACE_INTEREST(node_id, interface_id) = false;
        DOWNSTREAM_INTEREST(node_id, interface_id) = ndi;
        if
        :: last_type == non_root ->
            INTERFACE_ASSERT_STATE(node_id, interface_id) = al;
        :: last_type == root ->
            INTERFACE_ASSERT_STATE(node_id, interface_id) = na;
            if 
            :: UPSTREAM_INTEREST(node_id, interface_id) == ui ->
                UPSTREAM_INTEREST(node_id, interface_id) = nui
                ROUTER_INTEREST_UPSTREAM(node_id) = false;
                INTERFACE_ASSERT_STATE(node_id, interface_id) = na;
            :: else ->
                skip;
            fi;
        :: else ->
            skip
        fi;
        for (i : 0 .. (NB_OF_INTERFACES-1)) {
          //INTERFACE_ASSERT_NEIGHBOR(node_id, interface_id, i) = 0;
          INTERFACE_NEIGHBOR_RPC(node_id, interface_id, i) = INFINITE_METRIC;
          NEIGHBOR_INTEREST(node_id, interface_id, i) = false;
        }
    :: else ->
       printf("interface is still pumping");
    fi;
  }
}

/*Checks interface interest in multicast based on whether it has interested neighbors or not*/
inline check_interface_interest(node_id, interface_id) {
  byte i;
    atomic {
      bool interfaceInterest = false;
      /*Check if interface has interested neihbors */
      for (i : 0 .. (NB_OF_INTERFACES-1)) {
        if 
        :: NEIGHBOR_INTEREST(node_id,interface_id,i) == true  ->
            interfaceInterest = true;
            break;
        :: else ->
            skip
        fi;
      }
      if 
      :: interfaceInterest == true ->
          INTERFACE_INTEREST(node_id, interface_id) = true;
      :: else ->
          INTERFACE_INTEREST(node_id, interface_id) = false;
      fi;
    }
}

/*Checks if router already belongs to the tree, if it was already interested*/
inline check_in_tree(node_id) {

  atomic {
    byte i;
    bool routerInterest = false;
    for (i : 0 .. (NB_OF_INTERFACES-1)) {
      if
      :: INTERFACE_TYPE(node_id, i) == non_root && DOWNSTREAM_INTEREST(node_id, i)==di && INTERFACE_ASSERT_STATE(node_id, i)==aw ->
          routerInterest = true;
          break;
      :: INTERFACE_TYPE(node_id, i) == root && UPSTREAM_INTEREST(node_id, i) == ui ->
          routerInterest = true;
          break;
      :: else ->
          skip
      fi;
    }
    if 
    :: routerInterest == true ->
        ROUTER_INTEREST(node_id) = in;
    :: else ->
        ROUTER_INTEREST(node_id) = ni;
    fi;
  }
}

/*Verifies the assert state*/
inline verify_assert(node_id, interface_id){

  byte j;
  bool aseert_winner = false;
  atomic{
    if
    :: INTERFACE_TYPE(node_id, interface_id) == non_root && DOWNSTREAM_INTEREST(node_id, interface_id) == di ->
        //check if AW OR AL
        for (j : 0 .. (NB_OF_INTERFACES-1)) {
          if
          :: betterRpc(interface_id, MY_RPC(node_id), j, INTERFACE_NEIGHBOR_RPC(node_id, interface_id, j)) -> //I am AW
              aseert_winner = true;
          ::!betterRpc(interface_id, MY_RPC(node_id), j, INTERFACE_NEIGHBOR_RPC(node_id, interface_id, j)) -> //I am AL
              aseert_winner = false;
              break;
          fi;
        }
        if
        :: aseert_winner == true ->
            INTERFACE_ASSERT_STATE(node_id, interface_id) = aw;
        :: else ->
            INTERFACE_ASSERT_STATE(node_id, interface_id) = al;
        fi;
    :: INTERFACE_TYPE(node_id, interface_id) == root || (INTERFACE_TYPE(node_id, interface_id) == non_root && DOWNSTREAM_INTEREST(node_id, interface_id) == ndi) ->
        INTERFACE_ASSERT_STATE(node_id, interface_id) = na;
    :: else ->
        skip;
    fi;
  }
}

proctype InterfaceReceive(byte node_id; byte interface_id){

  mtype msg_type;
  byte neighbor_id;
  byte neighbor_rpc;

end:
  do
  :: nempty(ch[interface_id]) ->
    atomic {
      ch[interface_id] ? msg_type(neighbor_id, neighbor_rpc);

      if
      /* Assert message*/
      :: msg_type == assert_msg && neighbor_id != interface_id ->
          INTERFACE_NEIGHBOR_RPC(node_id, interface_id, neighbor_id) = neighbor_rpc;
          verify_assert(node_id,interface_id);
        if
        :: INTERFACE_ASSERT_STATE(node_id, interface_id) == aw ->
            ROUTER_INTEREST(node_id) = in;
        :: INTERFACE_ASSERT_STATE(node_id, interface_id) == al && 
              ROUTER_INTEREST_UPSTREAM(node_id) == false->
            ROUTER_INTEREST(node_id) = ni;
        :: else ->
          skip
        fi;
      /*Interest message: DONE*/ 
      :: msg_type == join_msg || msg_type == prune_msg ->
        if
        :: INTERFACE_TYPE(node_id, interface_id) != not_interface ->
          if
          :: msg_type == join_msg ->
              NEIGHBOR_INTEREST(node_id, interface_id, neighbor_id) = true;
          :: msg_type == prune_msg ->
              NEIGHBOR_INTEREST(node_id, interface_id, neighbor_id) = false;
          :: else ->
              skip;
          fi;
          check_interface_interest(node_id, interface_id);
        :: else ->
            skip
        fi;

        if 
        /*If non-root interface becomes DI*/
        :: INTERFACE_TYPE(node_id, interface_id) == non_root && 
              INTERFACE_INTEREST(node_id, interface_id) == true && 
              DOWNSTREAM_INTEREST(node_id, interface_id) == ndi ->
            DOWNSTREAM_INTEREST(node_id, interface_id) = di;
            sendMsg(node_id, assert_msg, interface_id, MY_RPC(node_id));
            verify_assert(node_id, interface_id); // to determine if I am the aw or al
            check_in_tree(node_id);

        /*If non-root interface becomes NDI*/
        :: INTERFACE_TYPE(node_id, interface_id) == non_root && 
              INTERFACE_INTEREST(node_id, interface_id) == false && 
              DOWNSTREAM_INTEREST(node_id, interface_id) == di ->
            DOWNSTREAM_INTEREST(node_id, interface_id) = ndi;
            INTERFACE_ASSERT_STATE(node_id, interface_id) = na;
            sendMsg(node_id, assert_msg, interface_id, INFINITE_METRIC);
            check_in_tree(node_id);
        
        /*If root interface becomes UI*/
        :: INTERFACE_TYPE(node_id, interface_id) == root && 
            INTERFACE_INTEREST(node_id, interface_id) == true && 
            UPSTREAM_INTEREST(node_id, interface_id) == nui ->
            UPSTREAM_INTEREST(node_id, interface_id) = ui;
            ROUTER_INTEREST_UPSTREAM(node_id) = true;
            check_in_tree(node_id);

        /*If root interface becomes NUI*/
        :: INTERFACE_TYPE(node_id, interface_id) == root && 
              INTERFACE_INTEREST(node_id, interface_id) == false && 
              UPSTREAM_INTEREST(node_id, interface_id) == ui ->
            UPSTREAM_INTEREST(node_id, interface_id) = nui;
            ROUTER_INTEREST_UPSTREAM(node_id) = false;
            check_in_tree(node_id);
          
        :: else ->
            skip
        fi;
      :: else ->
          skip
      fi;
    }
  od;
}

proctype InterfaceSend(byte node_id; byte interface_id){
  mtype last_interface_type = INTERFACE_TYPE(node_id, interface_id);
  mtype was_in_tree = ni;
  mtype last_assert_state = na;

end:

atomic{
  do
  /*Router becomes Interested*/
  :: ROUTER_INTEREST(node_id) == in && was_in_tree == ni && INTERFACE_TYPE(node_id, interface_id) == root && last_interface_type == root  ->
     was_in_tree = ROUTER_INTEREST(node_id);
     if
     :: INTERFACE_TYPE(node_id, interface_id) == root ->
          sendMsgUnicast(node_id, join_msg, interface_id, 0, INTERFACE_POTENTIAL_AW(node_id, interface_id))
     :: else ->
         skip;
     fi;


  /*Router becomes Not Interested*/
  :: ROUTER_INTEREST(node_id) == ni && was_in_tree == in && INTERFACE_TYPE(node_id, interface_id) == root && last_interface_type == root ->
     was_in_tree = ROUTER_INTEREST(node_id);
     if
     :: INTERFACE_TYPE(node_id, interface_id) == root ->
        sendMsgUnicast(node_id, prune_msg, interface_id, 0, INTERFACE_POTENTIAL_AW(node_id, interface_id));
     :: else ->
         skip;
     fi;


    /*Non_root becomes root*/
  :: INTERFACE_TYPE(node_id, interface_id) == root && last_interface_type == non_root  ->
     if 
     :: DOWNSTREAM_INTEREST(node_id, interface_id) == di || INTERFACE_INTEREST(node_id, interface_id) == true->
        sendMsg(node_id, assert_msg, interface_id, INFINITE_METRIC); //Send assertCancel
        UPSTREAM_INTEREST(node_id, interface_id) = ui; //If it was di it has interested neighbours so it becomes ui
     :: else ->
          UPSTREAM_INTEREST(node_id, interface_id) = nui;
     fi;
     last_interface_type = root;
     INTERFACE_ASSERT_STATE(node_id, interface_id) = na;
     DOWNSTREAM_INTEREST(node_id, interface_id) = ndi;
     check_in_tree(node_id);
     

  /*Root becomes non_root*/
  :: INTERFACE_TYPE(node_id, interface_id) == non_root && last_interface_type == root ->
     if 
     :: ROUTER_INTEREST(node_id) == in ->
          sendMsgUnicast(node_id, prune_msg, interface_id, 0, INTERFACE_POTENTIAL_AW(node_id, interface_id));

      /* If it has interested neighbors*/
     :: UPSTREAM_INTEREST(node_id, interface_id) == ui ->
          UPSTREAM_INTEREST(node_id, interface_id) = nui;
          DOWNSTREAM_INTEREST(node_id, interface_id) = di;
          sendMsg(node_id, assert_msg, interface_id, MY_RPC(node_id));
          verify_assert(node_id, interface_id);
          check_in_tree(node_id);
     :: else ->
          DOWNSTREAM_INTEREST(node_id, interface_id) = ndi;
          INTERFACE_ASSERT_STATE(node_id, interface_id) = na; 
     fi;
     last_interface_type = non_root;
     
  od;
  }
}

/*Unicast change, causing interface to change roles */
inline unicastChange(node_id, interface_id, new_type) {
  atomic {
    INTERFACE_TYPE(node_id, interface_id) = new_type;
  }
}

/*Potential AW changes due to unicast changes*/
inline potentialAW_change(node_id, interface_id, new_potetialAW) {
  atomic {
    if
    :: ROUTER_INTEREST(node_id) == in ->
        sendMsgUnicast(node_id, prune_msg, interface_id, 0, INTERFACE_POTENTIAL_AW(node_id, interface_id));
        sendMsgUnicast(node_id, join_msg, interface_id, 0, new_potetialAW);
    :: else ->
        skip;
    fi;
    INTERFACE_POTENTIAL_AW(node_id, interface_id) = new_potetialAW;
  }
}

/*Changes RPC*/
inline rpcChange(node_id, new_rpc) {
  byte interface_id = 0;
  atomic {
      MY_RPC(node_id) = new_rpc;
      for(interface_id: 0 .. (NB_OF_INTERFACES-1)){
        if
        :: DOWNSTREAM_INTEREST(node_id, interface_id) == di ->
            verify_assert(node_id, interface_id);
            if
            :: INTERFACE_ASSERT_STATE(node_id, interface_id) == aw ->
                ROUTER_INTEREST(node_id) = in;
            :: INTERFACE_ASSERT_STATE(node_id, interface_id) == al && ROUTER_INTEREST_UPSTREAM(node_id) == false->
                ROUTER_INTEREST(node_id) = ni;
            :: else ->
              skip
            fi;
            sendMsg(node_id, assert_msg, interface_id, MY_RPC(node_id));
        :: else ->
            skip
        fi;
      }
  }
}

/*Simulates an interface failure*/
inline interfaceFailure(node_id, interface_id){
  atomic {
    mtype last_type = INTERFACE_TYPE(node_id, interface_id);
    if
    :: INTERFACE_TYPE(node_id, interface_id) == root  ->

       if 
       :: ROUTER_INTEREST(node_id) == in ->
          sendMsgUnicast(node_id, prune_msg, interface_id, 0, INTERFACE_POTENTIAL_AW(node_id, interface_id))
       :: else ->
          skip
       fi;

       clearInterface(node_id, interface_id, last_type);
       INTERFACE_TYPE(node_id, interface_id) = not_interface;
       ROUTER_INTEREST(node_id) = ni;

    
    :: INTERFACE_TYPE(node_id, interface_id) == non_root ->
        if
        :: DOWNSTREAM_INTEREST(node_id, interface_id) == di ->
           sendMsg(node_id, assert_msg, interface_id, INFINITE_METRIC);
        :: else ->
          skip
        fi;

       clearInterface(node_id, interface_id, last_type);
       INTERFACE_TYPE(node_id, interface_id) = not_interface;
       ROUTER_INTEREST(node_id) = ni;

    :: else ->
      skip;
    fi;
  }
}

init {

  /*Node 0 initial conf*/
  node_info[0].my_rpc = 5
  //node_info[0].node_interface[0].interface_type = root
  node_info[0].node_interface[1].interface_type = non_root
  node_info[0].neighbors_at_each_interface[1] = (1 << 3)
  node_info[0].node_interface[2].interface_type = non_root
  node_info[0].neighbors_at_each_interface[2] = (1 << 4)

  /*Node 1 initial conf*/
  node_info[1].my_rpc = 10
  node_info[1].node_interface[3].interface_type = root
  node_info[1].node_interface[3].potential_aw = 1
  node_info[1].neighbors_at_each_interface[3] = (1 << 1)
  node_info[1].node_interface[5].interface_type = non_root
  node_info[1].neighbors_at_each_interface[5] = (1 << 6) | (1 << 7) | (1 << 8)

  /*Node 2 initial conf*/
  node_info[2].my_rpc = 15
  node_info[2].node_interface[4].interface_type = root
  node_info[2].node_interface[4].potential_aw = 2
  node_info[2].neighbors_at_each_interface[4] = (1 << 2)
  node_info[2].node_interface[6].interface_type = non_root
  node_info[2].node_interface[6].potential_aw = 5
  node_info[2].neighbors_at_each_interface[6] = (1 << 5) | (1 << 7) | (1 << 8)


  /*Node 3 initial conf*/
  node_info[3].my_rpc = 20
  node_info[3].node_interface[7].interface_type = root
  node_info[3].node_interface[7].potential_aw = 5
  node_info[3].neighbors_at_each_interface[7] = (1 << 5) | (1 << 6) | (1 << 8)

  /*Node 4 initial conf*/
  node_info[4].my_rpc = 25
  node_info[4].node_interface[8].interface_type = root
  node_info[4].node_interface[8].potential_aw = 6
  node_info[4].neighbors_at_each_interface[8] = (1 << 5) | (1 << 6) | (1 << 7)

  atomic{

    /*Node 0*/
    run InterfaceSend(0,1);
    run InterfaceReceive(0,1);
    
    run InterfaceSend(0,2);
    run InterfaceReceive(0,2);

    /*Node 1*/
    run InterfaceSend(1,3);
    run InterfaceReceive(1,3);
    
    run InterfaceSend(1,5);
    run InterfaceReceive(1,5);

    /*Node 2*/
    run InterfaceSend(2,4);
    run InterfaceReceive(2,4);

    run InterfaceSend(2,6);
    run InterfaceReceive(2,6);

    /*Node 3*/
    run InterfaceSend(3,7);
    run InterfaceReceive(3,7);

    /*Node 4*/
    run InterfaceSend(4,8);
    run InterfaceReceive(4,8);

    node_info[4].router_interest = in      
  } 

  atomic{

    node_info[3].router_interest = in
  }
}

/*Verification for when R4 and R3 are interested */
ltl ltl_test {(<>([](ROUTER_INTEREST(0)==in && ROUTER_INTEREST(1)==in && ROUTER_INTEREST(2)==ni &&
  DOWNSTREAM_INTEREST(0,1)==di && DOWNSTREAM_INTEREST(0,2)==ndi && DOWNSTREAM_INTEREST(1,5)==di && DOWNSTREAM_INTEREST(2,6)==di &&
  INTERFACE_ASSERT_STATE(0,1)==aw && INTERFACE_ASSERT_STATE(0,2)==na && INTERFACE_ASSERT_STATE(1,5)==aw && INTERFACE_ASSERT_STATE(2,6)==al)))}



  


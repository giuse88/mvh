
// synchronization group
/*struct thread_group synchronization_group_[MAX_THREAD];*/
//struct thread_group connection;

/*int get_free_index_connection(){ */
  /*for(int i=0; i < MAX_THREAD; i++)*/
     /*if (synchronization_group_[i].free)*/
        /*return i; */
  /*return -1; */
/*} */
/*void free_location( int index){*/
    /*RESET(&syscall_table_server_[index], sizeof(struct thread_group));*/
/*} */
/*int get_index_from_private_cookie(int cookie){*/
  /*for (int i=0; i < MAX_THREAD; i++)*/
      /*if (synchronization_group_[i].private.cookie == cookie)*/
          /*return i; */
  /*return -1; */
/*}*/
/*int get_index_from_public_cookie(int cookie) {*/
  /*for (int i =0; i < MAX_THREAD; i++)*/
      /*if (synchronization_group_[i].public.cookie == cookie)*/
          /*return i; */
  /*return -1; */
/*}*/



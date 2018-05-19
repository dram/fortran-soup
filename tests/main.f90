program main
  use cstrings
  use iso_c_binding
  use soup
  use soup_aux

  implicit none

  block
    integer(c_int) rc
    type(c_ptr) message, session, request, stream

    call cstring_initialize

    session = soup_session_sync_new()
    request = soup_session_request( &
         session, cstring('http://www.example.com'), c_null_ptr)
    stream = soup_request_send(request, c_null_ptr, c_null_ptr)
    print *, soup_request_get_content_length(request)

    session = soup_session_sync_new()
    message = soup_message_new( &
         cstring('GET'), cstring('http://www.example.com'))
    rc = soup_session_send_message(session, message)
    print *, rc

    call cstring_finalize
  end block

end program main

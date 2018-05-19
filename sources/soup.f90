module soup
  use iso_c_binding, only: c_int

  implicit none

  private c_int

  include "constants.f90"

  interface
     subroutine soup_message_headers_append(hdrs, name, value) bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr), value :: hdrs, name, value
     end subroutine soup_message_headers_append

     function soup_message_headers_get_one(hdrs, name) bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr), value :: hdrs, name
       type(c_ptr) soup_message_headers_get_one
     end function soup_message_headers_get_one

     function soup_message_new(method, uri_string) bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr), value :: method, uri_string
       type(c_ptr) soup_message_new
     end function soup_message_new

     subroutine soup_message_set_request( &
          msg, content_type, req_use, req_body, req_length) bind(c)
       use iso_c_binding, only: c_int, c_long, c_ptr
       type(c_ptr), value :: msg, content_type, req_body
       integer(c_int), value :: req_use
       integer(c_long), value :: req_length
     end subroutine soup_message_set_request

     function soup_session_sync_new() bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr) soup_session_sync_new
     end function soup_session_sync_new

     function soup_session_new() bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr) soup_session_new
     end function soup_session_new

     function soup_session_send(session, msg, cancellable, error) bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr), value :: session, msg, cancellable, error
       type(c_ptr) soup_session_send
     end function soup_session_send

     function soup_request_get_content_length(request) bind(c)
       use iso_c_binding, only: c_ptr, c_int64_t
       type(c_ptr), value :: request
       integer(c_int64_t) soup_request_get_content_length
     end function soup_request_get_content_length

     function soup_request_send(request, cancellable, error) bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr), value :: request, cancellable, error
       type(c_ptr) soup_request_send
     end function soup_request_send

     function soup_session_request(session, uri_string, error) bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr), value :: session, uri_string, error
       type(c_ptr) soup_session_request
     end function soup_session_request

     function soup_session_send_message(session, msg) bind(c)
       use iso_c_binding, only: c_int, c_ptr
       type(c_ptr), value :: session, msg
       integer(c_int) soup_session_send_message
     end function soup_session_send_message

  end interface
end module soup

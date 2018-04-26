module soup
  use iso_c_binding

  implicit none

  include "constants.f90"

  interface
     function soup_session_new() bind(c)
       use iso_c_binding, only: c_ptr
       type(c_ptr) soup_session_new
     end function soup_session_new

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
  end interface
end module soup

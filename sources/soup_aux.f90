module soup_aux
  use soup
  use iso_c_binding

  implicit none

  private

  public &
       soup_aux_message_new

  interface
     pure function strlen(s) bind(c)
       use iso_c_binding, only: c_size_t, c_ptr
       type(c_ptr), value :: s
       integer(c_size_t) strlen
     end function strlen
  end interface

contains

  function soup_aux_message_new(method, uri_string)
    character(*), intent(in) :: method, uri_string
    type(c_ptr) soup_aux_message_new

    character(:), allocatable, target :: method_buffer, uri_buffer

    method_buffer = method // char(0)
    uri_buffer = uri_string // char(0)
    soup_aux_message_new = &
         soup_message_new(c_loc(method_buffer), c_loc(uri_buffer))
  end function soup_aux_message_new

end module soup_aux

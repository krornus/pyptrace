nnoremap <F4> :make<CR>

if expand('%:t') == "StackMonitor.cpp"
    let b:pin="/home/spowell/research/pyitrace/tool/binaries/test-app"
    nnoremap <F5> :!clear && /home/spowell/research/pyitrace/pin/pin -t ./obj-intel64/StackMonitor.so -- <c-r><c-r>=b:pin<CR><CR>
elseif expand('%:t') == "server.c"
    :set makeprg=gcc\ server.c\ -o\ server
    nnoremap <F5> :!clear && ./server<CR>
endif

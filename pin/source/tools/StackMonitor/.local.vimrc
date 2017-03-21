
nnoremap <F4> :make<CR>
if expand('%:t') == "StackMonitor.cpp"
    nnoremap <F5> :!clear && /home/spowell/research/pyitrace/pin/pin -t ./obj-intel64/StackMonitor.so -- /bin/ls<CR>
    :131
elseif expand('%:t') == "server.c"
    :set makeprg=gcc\ server.c\ -o\ server
    nnoremap <F5> :!clear && ./server<CR>
    :65
endif

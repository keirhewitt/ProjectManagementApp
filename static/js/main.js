/*
    Project Management App - Master

    * Handles the dynamic HTML elements *
    
    TASK: Make the room.html task section dynamic
*/

var accordion = document.getElementsByClassName('container');

for (i=0; i<accordion.length; i++) {
  accordion[i].addEventListener('click', function () {
    this.classList.toggle('active')
  })
}

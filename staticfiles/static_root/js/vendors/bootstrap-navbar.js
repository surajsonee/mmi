/* -------------------------------------------------------------------------- 
|                                 Sparrow Navbar                                 
/* -------------------------------------------------------------------------- */


const bootstrapNavbarInit = () =>{
  const navbar = document.querySelector('.navbar-sparrow')

  if(navbar){
    const windowHeight = window.innerHeight;
    const handleAlpha = () => {
      const scrollTop = window.pageYOffset;
      let alpha = (scrollTop / windowHeight) * 2;
      (alpha >= 1) && (alpha = 1);
      navbar.style.backgroundColor = `rgba(0, 0, 0, ${alpha})`;
    }
    handleAlpha();
    document.addEventListener( 'scroll', () => handleAlpha() );

    // Top navigation background toggle on mobile
    navbar.addEventListener('show.bs.collapse', (e) => {
      e.currentTarget.classList.toggle('bg-black');
    });
    navbar.addEventListener('hide.bs.collapse', (e) => {
      e.currentTarget.classList.toggle('bg-black');
    });

  }

}
export default bootstrapNavbarInit;

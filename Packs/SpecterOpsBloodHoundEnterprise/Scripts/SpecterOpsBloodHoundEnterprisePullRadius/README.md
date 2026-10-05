Refreshes the BloodHound Enterprise radius targets on the open User, Computer, or Group indicator.

The script calls `bloodhound-principal-impact-get` with `view=radius` and writes the target list to the `bloodhoundradiustable` indicator field. A failed lookup leaves the field unchanged.
